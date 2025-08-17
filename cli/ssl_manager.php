#!/usr/bin/env php
<?php
/**
 * SSL Certificate Manager - PHP CLI Interface
 * Command-line interface for managing SSL certificates
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Yaml\Yaml;

class SSLManagerCommand extends Command
{
    private $config;
    private $dbConnection;

    protected function configure()
    {
        $this
            ->setName('ssl:manage')
            ->setDescription('SSL Certificate Management Operations')
            ->addArgument('action', InputArgument::REQUIRED, 'Action to perform (scan, list, renew, export)')
            ->addArgument('target', InputArgument::OPTIONAL, 'Target for the action')
            ->addOption('config', 'c', InputOption::VALUE_REQUIRED, 'Configuration file path', 'config/config.json')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Output format (table, json)', 'table')
            ->addOption('expiring', null, InputOption::VALUE_REQUIRED, 'Filter certificates expiring within N days')
            ->addOption('issuer', null, InputOption::VALUE_REQUIRED, 'Filter by issuer category')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show what would be done without executing');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->loadConfig($input->getOption('config'));
        $this->initDatabase();

        $action = $input->getArgument('action');
        $target = $input->getArgument('target');

        switch ($action) {
            case 'scan':
                return $this->scanCertificates($input, $output, $target);
            case 'list':
                return $this->listCertificates($input, $output);
            case 'renew':
                return $this->renewCertificate($input, $output, $target);
            case 'export':
                return $this->exportCertificates($input, $output);
            case 'stats':
                return $this->showStatistics($input, $output);
            default:
                $output->writeln("<error>Unknown action: {$action}</error>");
                return Command::FAILURE;
        }
    }

    private function loadConfig($configPath)
    {
        if (!file_exists($configPath)) {
            throw new \Exception("Configuration file not found: {$configPath}");
        }

        $this->config = json_decode(file_get_contents($configPath), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception("Invalid JSON in configuration file");
        }
    }

    private function initDatabase()
    {
        $dbConfig = $this->config['database'];
        
        switch ($dbConfig['type']) {
            case 'sqlite':
                $dsn = "sqlite:{$dbConfig['name']}";
                $this->dbConnection = new PDO($dsn);
                break;
            case 'mysql':
                $dsn = "mysql:host={$dbConfig['host']};port={$dbConfig['port']};dbname={$dbConfig['name']}";
                $this->dbConnection = new PDO($dsn, $dbConfig['username'], $dbConfig['password']);
                break;
            case 'postgresql':
                $dsn = "pgsql:host={$dbConfig['host']};port={$dbConfig['port']};dbname={$dbConfig['name']}";
                $this->dbConnection = new PDO($dsn, $dbConfig['username'], $dbConfig['password']);
                break;
            default:
                throw new \Exception("Unsupported database type: {$dbConfig['type']}");
        }

        $this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    private function scanCertificates(InputInterface $input, OutputInterface $output, $directory): int
    {
        if (!$directory) {
            $output->writeln("<error>Directory path required for scan operation</error>");
            return Command::FAILURE;
        }

        if (!is_dir($directory)) {
            $output->writeln("<error>Directory not found: {$directory}</error>");
            return Command::FAILURE;
        }

        $output->writeln("Scanning directory: {$directory}");

        try {
            $certificates = $this->parseCertificatesInDirectory($directory);
            
            $added = 0;
            $updated = 0;
            $errors = [];

            foreach ($certificates as $certData) {
                try {
                    if ($this->storeCertificate($certData)) {
                        $added++;
                    } else {
                        $updated++;
                    }
                } catch (Exception $e) {
                    $errors[] = "Error storing {$certData['file_path']}: " . $e->getMessage();
                }
            }

            $output->writeln("✓ Scan completed successfully");
            $output->writeln("  Certificates found: " . count($certificates));
            $output->writeln("  Certificates added: {$added}");
            $output->writeln("  Certificates updated: {$updated}");

            if (!empty($errors)) {
                $output->writeln("  Errors: " . count($errors));
                foreach ($errors as $error) {
                    $output->writeln("    - {$error}");
                }
            }

            return Command::SUCCESS;

        } catch (Exception $e) {
            $output->writeln("<error>Scan failed: " . $e->getMessage() . "</error>");
            return Command::FAILURE;
        }
    }

    private function listCertificates(InputInterface $input, OutputInterface $output): int
    {
        try {
            $format = $input->getOption('format');
            $expiring = $input->getOption('expiring');
            $issuer = $input->getOption('issuer');

            $sql = "SELECT id, common_name, issuer_category, days_until_expiry, is_expired, file_path, not_valid_after 
                    FROM certificates WHERE is_active = 1";
            $params = [];

            if ($expiring) {
                $sql .= " AND days_until_expiry <= ?";
                $params[] = $expiring;
            }

            if ($issuer) {
                $sql .= " AND issuer_category = ?";
                $params[] = $issuer;
            }

            $sql .= " ORDER BY days_until_expiry ASC LIMIT 50";

            $stmt = $this->dbConnection->prepare($sql);
            $stmt->execute($params);
            $certificates = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (empty($certificates)) {
                $output->writeln("No certificates found matching criteria.");
                return Command::SUCCESS;
            }

            if ($format === 'json') {
                $output->writeln(json_encode($certificates, JSON_PRETTY_PRINT));
            } else {
                $table = new Table($output);
                $table->setHeaders(['ID', 'Common Name', 'Issuer', 'Days', 'Status', 'Expires']);

                foreach ($certificates as $cert) {
                    $status = $cert['is_expired'] ? 'EXPIRED' : 'VALID';
                    if ($cert['days_until_expiry'] <= 30 && !$cert['is_expired']) {
                        $status = 'EXPIRING';
                    }

                    $table->addRow([
                        $cert['id'],
                        substr($cert['common_name'], 0, 25),
                        substr($cert['issuer_category'], 0, 12),
                        $cert['days_until_expiry'],
                        $status,
                        date('Y-m-d', strtotime($cert['not_valid_after']))
                    ]);
                }

                $table->render();
                $output->writeln("\nFound " . count($certificates) . " certificates");
            }

            return Command::SUCCESS;

        } catch (Exception $e) {
            $output->writeln("<error>Failed to list certificates: " . $e->getMessage() . "</error>");
            return Command::FAILURE;
        }
    }

    private function renewCertificate(InputInterface $input, OutputInterface $output, $certId): int
    {
        if (!$certId) {
            $output->writeln("<error>Certificate ID required for renewal</error>");
            return Command::FAILURE;
        }

        $dryRun = $input->getOption('dry-run');

        try {
            // Get certificate details
            $stmt = $this->dbConnection->prepare("SELECT * FROM certificates WHERE id = ? AND is_active = 1");
            $stmt->execute([$certId]);
            $cert = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$cert) {
                $output->writeln("<error>Certificate with ID {$certId} not found</error>");
                return Command::FAILURE;
            }

            $output->writeln("Certificate: {$cert['common_name']}");
            $output->writeln("Current expiry: {$cert['not_valid_after']}");
            $output->writeln("Days until expiry: {$cert['days_until_expiry']}");

            if ($dryRun) {
                $output->writeln("\n[DRY RUN] Would attempt renewal for this certificate");
                return Command::SUCCESS;
            }

            // Call Python renewal system
            $pythonScript = __DIR__ . '/../cli/ssl_manager.py';
            $command = "python3 {$pythonScript} renew certificate {$certId}";
            
            $output->writeln("\nCalling Python renewal system...");
            $result = shell_exec($command);
            
            if ($result) {
                $output->writeln($result);
                return Command::SUCCESS;
            } else {
                $output->writeln("<error>Renewal command failed</error>");
                return Command::FAILURE;
            }

        } catch (Exception $e) {
            $output->writeln("<error>Renewal failed: " . $e->getMessage() . "</error>");
            return Command::FAILURE;
        }
    }

    private function exportCertificates(InputInterface $input, OutputInterface $output): int
    {
        try {
            $format = $input->getOption('format');
            $expiring = $input->getOption('expiring');
            $issuer = $input->getOption('issuer');

            $sql = "SELECT c.*, co.owner_email, co.owner_username, co.owner_url, co.department, co.environment 
                    FROM certificates c 
                    LEFT JOIN certificate_ownership co ON c.id = co.certificate_id 
                    WHERE c.is_active = 1";
            $params = [];

            if ($expiring) {
                $sql .= " AND c.days_until_expiry <= ?";
                $params[] = $expiring;
            }

            if ($issuer) {
                $sql .= " AND c.issuer_category = ?";
                $params[] = $issuer;
            }

            $stmt = $this->dbConnection->prepare($sql);
            $stmt->execute($params);
            $certificates = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($format === 'json') {
                $output->writeln(json_encode($certificates, JSON_PRETTY_PRINT));
            } else {
                // CSV format
                $output->writeln("ID,Common Name,Issuer,Days Until Expiry,Owner Email,Environment,File Path");
                foreach ($certificates as $cert) {
                    $output->writeln(sprintf(
                        "%d,\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\"",
                        $cert['id'],
                        $cert['common_name'],
                        $cert['issuer_category'],
                        $cert['days_until_expiry'],
                        $cert['owner_email'] ?? '',
                        $cert['environment'] ?? '',
                        $cert['file_path']
                    ));
                }
            }

            return Command::SUCCESS;

        } catch (Exception $e) {
            $output->writeln("<error>Export failed: " . $e->getMessage() . "</error>");
            return Command::FAILURE;
        }
    }

    private function showStatistics(InputInterface $input, OutputInterface $output): int
    {
        try {
            // Total certificates
            $stmt = $this->dbConnection->query("SELECT COUNT(*) FROM certificates WHERE is_active = 1");
            $total = $stmt->fetchColumn();

            // Expired certificates
            $stmt = $this->dbConnection->query("SELECT COUNT(*) FROM certificates WHERE is_active = 1 AND is_expired = 1");
            $expired = $stmt->fetchColumn();

            // Expiring soon
            $stmt = $this->dbConnection->query("SELECT COUNT(*) FROM certificates WHERE is_active = 1 AND days_until_expiry <= 30 AND is_expired = 0");
            $expiring30 = $stmt->fetchColumn();

            $stmt = $this->dbConnection->query("SELECT COUNT(*) FROM certificates WHERE is_active = 1 AND days_until_expiry <= 60 AND is_expired = 0");
            $expiring60 = $stmt->fetchColumn();

            // By issuer
            $stmt = $this->dbConnection->query("SELECT issuer_category, COUNT(*) as count FROM certificates WHERE is_active = 1 GROUP BY issuer_category");
            $byIssuer = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $output->writeln("Certificate Statistics:");
            $output->writeln("  Total certificates: {$total}");
            $output->writeln("  Expired certificates: {$expired}");
            $output->writeln("  Expiring in 30 days: {$expiring30}");
            $output->writeln("  Expiring in 60 days: {$expiring60}");

            $output->writeln("\nBy Issuer:");
            foreach ($byIssuer as $issuer) {
                $output->writeln("  {$issuer['issuer_category']}: {$issuer['count']}");
            }

            return Command::SUCCESS;

        } catch (Exception $e) {
            $output->writeln("<error>Failed to get statistics: " . $e->getMessage() . "</error>");
            return Command::FAILURE;
        }
    }

    private function parseCertificatesInDirectory($directory): array
    {
        $certificates = [];
        $extensions = ['.pem', '.crt', '.cer', '.p7b', '.p7c'];
        
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                if (in_array('.' . $extension, $extensions)) {
                    try {
                        $certData = $this->parseCertificateFile($file->getPathname());
                        if ($certData) {
                            $certificates = array_merge($certificates, $certData);
                        }
                    } catch (Exception $e) {
                        // Log error but continue processing
                        error_log("Error parsing {$file->getPathname()}: " . $e->getMessage());
                    }
                }
            }
        }
        
        return $certificates;
    }

    private function parseCertificateFile($filePath): array
    {
        $content = file_get_contents($filePath);
        if (!$content) {
            throw new Exception("Could not read file: {$filePath}");
        }

        $certificates = [];
        
        // Try to parse as PEM
        if (strpos($content, '-----BEGIN CERTIFICATE-----') !== false) {
            $certStrings = explode('-----END CERTIFICATE-----', $content);
            
            foreach ($certStrings as $i => $certString) {
                if (trim($certString)) {
                    $certString .= '-----END CERTIFICATE-----';
                    $certData = $this->extractCertificateInfo($certString, $filePath . "#" . $i);
                    if ($certData) {
                        $certificates[] = $certData;
                    }
                }
            }
        }
        
        return $certificates;
    }

    private function extractCertificateInfo($certString, $filePath): ?array
    {
        $cert = openssl_x509_parse($certString);
        if (!$cert) {
            return null;
        }

        $now = time();
        $expiryTime = $cert['validTo_time_t'];
        $daysUntilExpiry = floor(($expiryTime - $now) / 86400);

        return [
            'file_path' => $filePath,
            'serial_number' => $cert['serialNumber'] ?? '',
            'common_name' => $cert['subject']['CN'] ?? '',
            'not_valid_before' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
            'not_valid_after' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
            'days_until_expiry' => $daysUntilExpiry,
            'is_expired' => $daysUntilExpiry <= 0,
            'issuer_info' => json_encode($cert['issuer']),
            'subject_info' => json_encode($cert['subject']),
            'subject_alt_names' => json_encode($cert['extensions']['subjectAltName'] ?? []),
            'issuer_category' => $this->categorizeIssuer($cert['issuer']['CN'] ?? ''),
            'certificate_type' => 'server', // Simplified
            'signature_algorithm' => $cert['signatureTypeSN'] ?? ''
        ];
    }

    private function categorizeIssuer($issuerCN): string
    {
        $issuerLower = strtolower($issuerCN);
        
        if (strpos($issuerLower, 'let\'s encrypt') !== false || strpos($issuerLower, 'letsencrypt') !== false) {
            return 'letsencrypt';
        } elseif (strpos($issuerLower, 'digicert') !== false) {
            return 'digicert';
        } elseif (strpos($issuerLower, 'comodo') !== false || strpos($issuerLower, 'sectigo') !== false) {
            return 'comodo';
        } elseif (strpos($issuerLower, 'amazon') !== false || strpos($issuerLower, 'aws') !== false) {
            return 'aws';
        } elseif (strpos($issuerLower, 'cloudflare') !== false) {
            return 'cloudflare';
        } else {
            return 'other';
        }
    }

    private function storeCertificate($certData): bool
    {
        // Check if certificate exists
        $stmt = $this->dbConnection->prepare("SELECT id FROM certificates WHERE serial_number = ? AND file_path = ?");
        $stmt->execute([$certData['serial_number'], $certData['file_path']]);
        $existing = $stmt->fetch();

        if ($existing) {
            // Update existing
            $sql = "UPDATE certificates SET 
                    days_until_expiry = ?, 
                    is_expired = ?, 
                    updated_at = CURRENT_TIMESTAMP,
                    last_scanned = CURRENT_TIMESTAMP
                    WHERE id = ?";
            $stmt = $this->dbConnection->prepare($sql);
            $stmt->execute([
                $certData['days_until_expiry'],
                $certData['is_expired'] ? 1 : 0,
                $existing['id']
            ]);
            return false; // Updated, not added
        } else {
            // Insert new
            $sql = "INSERT INTO certificates (
                file_path, serial_number, common_name, not_valid_before, not_valid_after,
                days_until_expiry, is_expired, issuer_info, subject_info, subject_alt_names,
                issuer_category, certificate_type, signature_algorithm, created_at, updated_at, last_scanned
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
            
            $stmt = $this->dbConnection->prepare($sql);
            $stmt->execute([
                $certData['file_path'],
                $certData['serial_number'],
                $certData['common_name'],
                $certData['not_valid_before'],
                $certData['not_valid_after'],
                $certData['days_until_expiry'],
                $certData['is_expired'] ? 1 : 0,
                $certData['issuer_info'],
                $certData['subject_info'],
                $certData['subject_alt_names'],
                $certData['issuer_category'],
                $certData['certificate_type'],
                $certData['signature_algorithm']
            ]);
            return true; // Added
        }
    }
}

// Create and run the application
$application = new Application('SSL Certificate Manager PHP CLI', '1.0.0');
$application->add(new SSLManagerCommand());
$application->setDefaultCommand('ssl:manage');
$application->run();
