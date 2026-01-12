"""
Celery Configuration
Supports multiple message broker backends: RabbitMQ, Redis, AWS SQS, Azure Service Bus
"""

import os
from kombu import Exchange, Queue

# ============================================================================
# BROKER CONFIGURATION
# ============================================================================

# Broker URL - supports multiple backends
# Examples:
#   RabbitMQ: 'amqp://user:pass@localhost:5672//'
#   Redis: 'redis://localhost:6379/0'
#   AWS SQS: 'sqs://AWS_ACCESS_KEY:AWS_SECRET_KEY@'
#   Azure Service Bus: 'azureservicebus://...'

broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

# Result backend - where task results are stored
result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

# ============================================================================
# TASK CONFIGURATION
# ============================================================================

# Task serialization
task_serializer = 'json'
result_serializer = 'json'
accept_content = ['json']
timezone = 'UTC'
enable_utc = True

# Task result expiration (24 hours)
result_expires = 86400

# Task acknowledgement
task_acks_late = True
task_reject_on_worker_lost = True

# Task time limits
task_time_limit = 600  # 10 minutes hard limit
task_soft_time_limit = 540  # 9 minutes soft limit

# Worker configuration
worker_prefetch_multiplier = 4
worker_max_tasks_per_child = 1000
worker_disable_rate_limits = False

# ============================================================================
# QUEUE CONFIGURATION WITH PRIORITIES
# ============================================================================

task_default_queue = 'normal'
task_default_exchange = 'sslmgr'
task_default_routing_key = 'normal'

# Define exchanges
task_default_exchange_type = 'topic'

# Queue definitions with priority levels
task_queues = (
    # Critical queue - certificates expiring in < 7 days
    Queue(
        'critical',
        Exchange('sslmgr', type='topic'),
        routing_key='critical',
        queue_arguments={'x-max-priority': 10}
    ),

    # High priority queue - certificates expiring in < 15 days
    Queue(
        'high',
        Exchange('sslmgr', type='topic'),
        routing_key='high',
        queue_arguments={'x-max-priority': 7}
    ),

    # Normal queue - regular operations
    Queue(
        'normal',
        Exchange('sslmgr', type='topic'),
        routing_key='normal',
        queue_arguments={'x-max-priority': 5}
    ),

    # Low priority queue - background tasks
    Queue(
        'low',
        Exchange('sslmgr', type='topic'),
        routing_key='low',
        queue_arguments={'x-max-priority': 3}
    ),
)

# Task routing
task_routes = {
    # Critical renewals
    'queue.tasks.renew_certificate_urgent': {
        'queue': 'critical',
        'routing_key': 'critical',
        'priority': 10
    },

    # High priority renewals
    'queue.tasks.renew_certificate_high': {
        'queue': 'high',
        'routing_key': 'high',
        'priority': 7
    },

    # Normal renewals
    'queue.tasks.renew_certificate': {
        'queue': 'normal',
        'routing_key': 'normal',
        'priority': 5
    },

    # Validation tasks
    'queue.tasks.validate_certificate': {
        'queue': 'normal',
        'routing_key': 'normal',
        'priority': 5
    },

    # Threat intelligence
    'queue.tasks.check_certificate_threats': {
        'queue': 'normal',
        'routing_key': 'normal',
        'priority': 4
    },

    # DNS validation
    'queue.tasks.validate_dns_for_certificate': {
        'queue': 'normal',
        'routing_key': 'normal',
        'priority': 4
    },

    # Background tasks
    'queue.tasks.scan_desktop': {
        'queue': 'low',
        'routing_key': 'low',
        'priority': 3
    },

    # Monitoring tasks
    'queue.tasks.monitor_expiry_and_queue_renewals': {
        'queue': 'normal',
        'routing_key': 'normal',
        'priority': 6
    },
}

# ============================================================================
# BEAT SCHEDULE (Periodic Tasks)
# ============================================================================

from celery.schedules import crontab

beat_schedule = {
    # Monitor expiry every 4 hours
    'monitor-expiry-4h': {
        'task': 'queue.tasks.monitor_expiry_and_queue_renewals',
        'schedule': crontab(minute=0, hour='*/4'),
        'options': {'queue': 'normal', 'priority': 6}
    },

    # Daily threat intelligence scan at 2am
    'daily-threat-scan': {
        'task': 'queue.tasks.daily_threat_intelligence_scan',
        'schedule': crontab(hour=2, minute=0),
        'options': {'queue': 'normal', 'priority': 4}
    },

    # Weekly desktop scan - Sunday 3am
    'weekly-desktop-scan': {
        'task': 'queue.tasks.scan_desktop',
        'schedule': crontab(hour=3, minute=0, day_of_week=0),
        'options': {'queue': 'low', 'priority': 3},
        'kwargs': {'save_to_database': True}
    },
}

# ============================================================================
# MONITORING AND LOGGING
# ============================================================================

# Task events
worker_send_task_events = True
task_send_sent_event = True

# Logging
worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s'

# ============================================================================
# RATE LIMITING
# ============================================================================

# Task rate limits (to avoid overwhelming external APIs)
task_annotations = {
    'queue.tasks.renew_certificate': {'rate_limit': '100/m'},  # 100 per minute
    'queue.tasks.check_certificate_threats': {'rate_limit': '60/m'},  # 60 per minute (API limit)
    'queue.tasks.validate_dns_for_certificate': {'rate_limit': '120/m'},  # 120 per minute
}

# ============================================================================
# RETRY CONFIGURATION
# ============================================================================

# Default retry policy
task_default_retry_delay = 300  # 5 minutes
task_max_retries = 3

# ============================================================================
# BROKER SPECIFIC SETTINGS
# ============================================================================

# RabbitMQ specific
broker_connection_retry = True
broker_connection_retry_on_startup = True
broker_connection_max_retries = 10

# Redis specific
redis_max_connections = 50
redis_socket_keepalive = True
redis_socket_timeout = 120

# Visibility timeout (how long before task is requeued if worker dies)
broker_transport_options = {
    'visibility_timeout': 3600,  # 1 hour
    'max_retries': 3,
    'interval_start': 0,
    'interval_step': 0.2,
    'interval_max': 0.5,
}

# ============================================================================
# RESULT BACKEND SETTINGS
# ============================================================================

# Result cache
result_cache_max = 10000

# Result compression
result_compression = 'gzip'

# Result extended metadata
result_extended = True

# ============================================================================
# WORKER POOL SETTINGS
# ============================================================================

# Worker pool type (prefork, eventlet, gevent)
worker_pool = 'prefork'

# Concurrency (number of worker processes)
worker_concurrency = os.cpu_count() * 2

# Worker autoscaling
worker_autoscaler = '10,3'  # Max 10, min 3 workers

# ============================================================================
# SECURITY SETTINGS
# ============================================================================

# Task message security (if needed)
# task_serializer = 'auth'
# result_serializer = 'auth'
# security_key = os.getenv('CELERY_SECURITY_KEY')
# security_certificate = os.getenv('CELERY_SECURITY_CERT')
# security_cert_store = os.getenv('CELERY_SECURITY_CERT_STORE')
