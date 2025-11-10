# Additional models for new features
from datetime import datetime, timezone
from app import db

class Outcome(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')  # Pending, Completed
    deadline = db.Column(db.Date)  # Deadline for the outcome
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    completed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    task = db.relationship('Task', backref='outcomes')
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
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    marked_complete_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    marked_complete_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    project = db.relationship('Project', backref='approvals')
    marked_complete_by = db.relationship('User', foreign_keys=[marked_complete_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])

class TaskApproval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    marked_complete_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    marked_complete_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    task = db.relationship('Task', backref='approvals')
    marked_complete_by = db.relationship('User', foreign_keys=[marked_complete_by_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])

class ManualTaskDependency(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    dependency_name = db.Column(db.String(200), nullable=False)
    dependency_description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')  # Pending, Completed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    task = db.relationship('Task', backref='manual_dependencies')