"""
Job Tracker
Tracks status of certificate renewal and validation jobs in the message queue
Provides visibility into job progress and history
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from database.models import Base


class JobRecord(Base):
    """Job record in database"""

    __tablename__ = 'job_queue'

    id = Column(Integer, primary_key=True)
    task_id = Column(String(100), unique=True, nullable=False, index=True)
    task_name = Column(String(200), nullable=False, index=True)

    # Job details
    certificate_id = Column(Integer, index=True)
    job_type = Column(String(50), index=True)  # renewal, validation, threat_check, dns_validate
    priority = Column(String(20))  # critical, high, normal, low
    queue_name = Column(String(50))

    # Status tracking
    status = Column(String(50), default='queued', index=True)  # queued, running, completed, failed, retrying
    progress_percent = Column(Float, default=0.0)

    # Timestamps
    queued_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # Results
    result = Column(JSON)
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)

    # Additional metadata
    metadata = Column(JSON)


class JobTracker:
    """Tracks and manages certificate operation jobs"""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)

        # Ensure job table exists
        self._create_table()

    def _create_table(self):
        """Create job tracking table if it doesn't exist"""
        try:
            JobRecord.__table__.create(self.db_manager.engine, checkfirst=True)
        except Exception as e:
            self.logger.warning(f"Job table may already exist: {e}")

    def create_job(self, task_id: str, task_name: str, certificate_id: int = None,
                  job_type: str = 'renewal', priority: str = 'normal',
                  queue_name: str = 'normal', metadata: Dict = None) -> JobRecord:
        """Create a new job record"""
        session = self.db_manager.get_session()

        try:
            job = JobRecord(
                task_id=task_id,
                task_name=task_name,
                certificate_id=certificate_id,
                job_type=job_type,
                priority=priority,
                queue_name=queue_name,
                status='queued',
                queued_at=datetime.utcnow(),
                metadata=metadata or {}
            )

            session.add(job)
            session.commit()

            self.logger.info(f"Created job {task_id} for certificate {certificate_id}")
            return job

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error creating job: {e}")
            raise
        finally:
            session.close()

    def mark_running(self, task_id: str) -> bool:
        """Mark job as running"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                job.status = 'running'
                job.started_at = datetime.utcnow()
                session.commit()
                return True
            return False

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error marking job as running: {e}")
            return False
        finally:
            session.close()

    def update_progress(self, task_id: str, progress_percent: float) -> bool:
        """Update job progress"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                job.progress_percent = min(100.0, max(0.0, progress_percent))
                session.commit()
                return True
            return False

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error updating progress: {e}")
            return False
        finally:
            session.close()

    def mark_completed(self, task_id: str, result: Dict) -> bool:
        """Mark job as completed"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                job.status = 'completed'
                job.completed_at = datetime.utcnow()
                job.progress_percent = 100.0
                job.result = result
                session.commit()

                self.logger.info(f"Job {task_id} completed successfully")
                return True
            return False

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error marking job as completed: {e}")
            return False
        finally:
            session.close()

    def mark_failed(self, task_id: str, error_message: str) -> bool:
        """Mark job as failed"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                job.status = 'failed'
                job.completed_at = datetime.utcnow()
                job.error_message = error_message
                session.commit()

                self.logger.error(f"Job {task_id} failed: {error_message}")
                return True
            return False

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error marking job as failed: {e}")
            return False
        finally:
            session.close()

    def mark_retrying(self, task_id: str) -> bool:
        """Mark job as retrying"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                job.status = 'retrying'
                job.retry_count += 1
                session.commit()

                self.logger.info(f"Job {task_id} retrying (attempt {job.retry_count})")
                return True
            return False

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error marking job as retrying: {e}")
            return False
        finally:
            session.close()

    def get_job_status(self, task_id: str) -> Optional[Dict]:
        """Get job status"""
        session = self.db_manager.get_session()

        try:
            job = session.query(JobRecord).filter_by(task_id=task_id).first()
            if job:
                return {
                    'task_id': job.task_id,
                    'task_name': job.task_name,
                    'certificate_id': job.certificate_id,
                    'job_type': job.job_type,
                    'status': job.status,
                    'priority': job.priority,
                    'progress_percent': job.progress_percent,
                    'queued_at': job.queued_at.isoformat() if job.queued_at else None,
                    'started_at': job.started_at.isoformat() if job.started_at else None,
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                    'retry_count': job.retry_count,
                    'result': job.result,
                    'error_message': job.error_message
                }
            return None

        except Exception as e:
            self.logger.error(f"Error getting job status: {e}")
            return None
        finally:
            session.close()

    def get_active_jobs(self, certificate_id: int = None) -> List[Dict]:
        """Get all active jobs"""
        session = self.db_manager.get_session()

        try:
            query = session.query(JobRecord).filter(
                JobRecord.status.in_(['queued', 'running', 'retrying'])
            )

            if certificate_id:
                query = query.filter_by(certificate_id=certificate_id)

            jobs = query.all()

            return [
                {
                    'task_id': job.task_id,
                    'certificate_id': job.certificate_id,
                    'job_type': job.job_type,
                    'status': job.status,
                    'priority': job.priority,
                    'progress_percent': job.progress_percent,
                    'queued_at': job.queued_at.isoformat() if job.queued_at else None
                }
                for job in jobs
            ]

        except Exception as e:
            self.logger.error(f"Error getting active jobs: {e}")
            return []
        finally:
            session.close()

    def get_queue_statistics(self) -> Dict:
        """Get queue statistics"""
        session = self.db_manager.get_session()

        try:
            stats = {
                'queued': session.query(JobRecord).filter_by(status='queued').count(),
                'running': session.query(JobRecord).filter_by(status='running').count(),
                'retrying': session.query(JobRecord).filter_by(status='retrying').count(),
                'completed_24h': session.query(JobRecord).filter(
                    JobRecord.status == 'completed',
                    JobRecord.completed_at >= datetime.utcnow() - timedelta(hours=24)
                ).count(),
                'failed_24h': session.query(JobRecord).filter(
                    JobRecord.status == 'failed',
                    JobRecord.completed_at >= datetime.utcnow() - timedelta(hours=24)
                ).count(),
                'by_priority': {},
                'by_type': {}
            }

            # Count by priority
            for priority in ['critical', 'high', 'normal', 'low']:
                count = session.query(JobRecord).filter(
                    JobRecord.priority == priority,
                    JobRecord.status.in_(['queued', 'running', 'retrying'])
                ).count()
                stats['by_priority'][priority] = count

            # Count by type
            for job_type in ['renewal', 'validation', 'threat_check', 'dns_validate']:
                count = session.query(JobRecord).filter(
                    JobRecord.job_type == job_type,
                    JobRecord.status.in_(['queued', 'running', 'retrying'])
                ).count()
                stats['by_type'][job_type] = count

            return stats

        except Exception as e:
            self.logger.error(f"Error getting queue statistics: {e}")
            return {}
        finally:
            session.close()

    def cleanup_old_jobs(self, days: int = 30) -> int:
        """Clean up job records older than specified days"""
        session = self.db_manager.get_session()

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            deleted = session.query(JobRecord).filter(
                JobRecord.completed_at < cutoff_date,
                JobRecord.status.in_(['completed', 'failed'])
            ).delete()

            session.commit()

            self.logger.info(f"Cleaned up {deleted} old job records")
            return deleted

        except Exception as e:
            session.rollback()
            self.logger.error(f"Error cleaning up old jobs: {e}")
            return 0
        finally:
            session.close()
