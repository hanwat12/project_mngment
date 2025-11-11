from datetime import datetime, timezone
from app import db
from models import Task, Project, User # Added import for Task/Project/User for clarity, though typically Flask-SQLAlchemy handles deferred references

class Outcome(db.Model):
    __tablename__ = 'outcome'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')
    deadline = db.Column(db.Date)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=False)
    # FIX: Foreign key 'user.id' changed to 'users.id'
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    completed_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    task = db.relationship('Task', backref=db.backref('outcomes', lazy='dynamic', cascade='all, delete-orphan'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    completed_by = db.relationship('User', foreign_keys=[completed_by_id])

    def mark_completed(self, user_id):
        """Mark outcome as completed"""
        self.status = 'Completed'
        self.completed_by_id = user_id
        self.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        
    def is_overdue(self):
        """Check if outcome is overdue"""
        if self.deadline and self.status != 'Completed':
            from datetime import date
            return date.today() > self.deadline
        return False


class ProjectApproval(db.Model):
    __tablename__ = 'project_approval'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    # FIX: Foreign key 'user.id' changed to 'users.id'
    marked_complete_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    marked_complete_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    project = db.relationship('Project', backref=db.backref('approvals', lazy='dynamic', cascade='all, delete-orphan'))
    marked_complete_by = db.relationship('User', foreign_keys=[marked_complete_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])


class TaskApproval(db.Model):
    __tablename__ = 'task_approval'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=False)
    # FIX: Foreign key 'user.id' changed to 'users.id'
    marked_complete_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    marked_complete_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    task = db.relationship('Task', backref=db.backref('approvals', lazy='dynamic', cascade='all, delete-orphan'))
    marked_complete_by = db.relationship('User', foreign_keys=[marked_complete_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])


class ManualTaskDependency(db.Model):
    __tablename__ = 'manual_task_dependency'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=False)
    dependency_name = db.Column(db.String(200), nullable=False)
    dependency_description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')  # Pending, Completed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    task = db.relationship('Task', backref=db.backref('manual_dependencies', lazy='dynamic', cascade='all, delete-orphan'))
