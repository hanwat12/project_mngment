from datetime import datetime, timezone
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # Admin, Manager, User
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    skills = db.Column(db.Text)

    # Relationships
    managed_users = db.relationship(
        'User',
        primaryjoin='User.id == User.manager_id',
        backref=db.backref('manager', remote_side=[id]),
        lazy='dynamic'
    )
    projects_created = db.relationship(
        'Project',
        foreign_keys='Project.created_by_id',
        backref='creator',
        lazy='dynamic'
    )
    projects_assigned = db.relationship(
        'Project',
        secondary='project_assignments',
        back_populates='assigned_users',
        lazy='dynamic'
    )
    tasks_created = db.relationship(
        'Task',
        foreign_keys='Task.created_by_id',
        backref='creator',
        lazy='dynamic'
    )
    tasks_assigned = db.relationship(
        'Task',
        foreign_keys='Task.assigned_to_id',
        backref='assigned_user',
        lazy='dynamic'
    )
    
    # === FIX: Explicitly ties to Comment.author_id to resolve foreign key ambiguity ===
    comments = db.relationship(
        'Comment', 
        foreign_keys='Comment.author_id',
        backref='author', 
        lazy='dynamic'
    )
    

    
    permissions = db.relationship(
        'UserPermission',
        backref='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, module, action):
        """Check if user has specific permission"""
        if self.role == 'Admin':
            return True

        permission = UserPermission.query.filter_by(
            user_id=self.id,
            module=module,
            action=action
        ).first()
        return permission.granted if permission else False

    def get_accessible_projects(self):
        """Get projects user can access based on role and permissions"""
        if self.role == 'Admin':
            return Project.query.all()
        elif self.role == 'Manager':
            created = Project.query.filter_by(created_by_id=self.id).all()
            assigned = self.projects_assigned.all()
            return list(set(created + assigned))
        else:
            return self.projects_assigned.all()

    def get_accessible_tasks(self):
        """Get tasks user can access based on role and permissions"""
        if self.role == 'Admin':
            return Task.query.all()
        elif self.role == 'Manager':
            created = Task.query.filter_by(created_by_id=self.id).all()
            assigned = Task.query.filter_by(assigned_to_id=self.id).all()
            return list(set(created + assigned))
        else:
            return Task.query.filter_by(assigned_to_id=self.id).all()


class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='In Progress')  # Just Started, In Progress, Completed
    progress = db.Column(db.Integer, default=0)  # 0-100%
    deadline = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    tasks = db.relationship('Task', backref='project', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='project', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('Document', backref='project', lazy='dynamic', cascade='all, delete-orphan')
    assigned_users = db.relationship('User', secondary='project_assignments', back_populates='projects_assigned')

    def calculate_progress(self):
        """Calculate project progress based on completed tasks"""
        total_tasks = self.tasks.count()
        if total_tasks == 0:
            return 0
        completed_tasks = self.tasks.filter_by(status='Completed').count()
        return int((completed_tasks / total_tasks) * 100)

    def update_progress(self):
        """Update project progress and save to database"""
        self.progress = self.calculate_progress()
        if self.progress == 100:
            self.status = 'Completed'
        elif self.progress > 0:
            self.status = 'In Progress'
        else:
            self.status = 'Just Started'
        db.session.commit()

    def mark_completed(self, user_id=None):
        """Mark project as completed with approval workflow"""
        from models_extensions import ProjectApproval

        if user_id:
            approval = ProjectApproval(
                project_id=self.id,
                marked_complete_by_id=user_id,
                status='Pending'
            )
            db.session.add(approval)
            self.status = 'Pending Approval'
        else:
            self.status = 'Completed'

        db.session.commit()

    def is_overdue(self):
        """Check if project is overdue"""
        if self.deadline and self.status != 'Completed':
            from datetime import date
            return date.today() > self.deadline
        return False


class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')  # Pending, In Progress, Completed, Overdue
    priority = db.Column(db.String(20), default='Medium')  # Low, Medium, High
    deadline = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    dependent_on_task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)
    reassigned_from_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    skill_match_percentage = db.Column(db.Integer, default=0)

    # Relationships
    comments = db.relationship('Comment', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('Document', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    dependent_task = db.relationship('Task', remote_side=[id], backref='dependent_tasks')
    reassigned_from = db.relationship('User', foreign_keys=[reassigned_from_id])

    def mark_completed(self, user_id=None):
        """Mark task as completed and update project progress"""
        from models_extensions import TaskApproval

        if user_id:
            approval = TaskApproval(
                task_id=self.id,
                marked_complete_by_id=user_id,
                status='Pending'
            )
            db.session.add(approval)
            self.status = 'Pending Approval'
        else:
            self.status = 'Completed'
            self.completed_at = datetime.now(timezone.utc)

        db.session.commit()

        # Update project progress only if actually completed
        if self.status == 'Completed':
            project = Project.query.get(self.project_id)
            if project:
                project.update_progress()

    def is_overdue(self):
        """Check if task is overdue"""
        if self.deadline and self.status != 'Completed':
            from datetime import date
            return date.today() > self.deadline
        return False

    def calculate_outcome_progress(self):
        """Calculate task progress based on outcomes completion"""
        from models_extensions import Outcome
        total_outcomes = Outcome.query.filter_by(task_id=self.id).count()
        if total_outcomes == 0:
            return 0

        completed_outcomes = Outcome.query.filter_by(task_id=self.id, status='Completed').count()
        return round((completed_outcomes / total_outcomes) * 100)

    def get_progress_percentage(self):
        """Get task progress as percentage based on outcomes"""
        return self.calculate_outcome_progress()


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))
# Secondary user ID, perhaps for mentions


class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))

    # Relationships
    uploaded_by = db.relationship('User', backref='uploaded_documents')


class UserPermission(db.Model):
    __tablename__ = 'user_permissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    module = db.Column(db.String(50), nullable=False)  # Proj, Proj-team, Proj doc, Proj Dis., task
    action = db.Column(db.String(20), nullable=False)  # View, Add, Edit, Delete, Download
    granted = db.Column(db.Boolean, default=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'module', 'action'),)


class Milestone(db.Model):
    __tablename__ = 'milestones'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='Pending')  # Pending, Completed
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    project = db.relationship('Project', backref='milestones')


class UserType(db.Model):
    __tablename__ = 'user_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    created_by = db.relationship('User', backref='created_user_types')


class DocumentComment(db.Model):
    __tablename__ = 'document_comments'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    author = db.relationship('User', backref='document_comments')
    document = db.relationship('Document', backref='comments')


class DocumentVersion(db.Model):
    __tablename__ = 'document_versions'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    file_size = db.Column(db.Integer)
    is_current = db.Column(db.Boolean, default=False)

    # Relationships
    document = db.relationship('Document', backref='versions')
    uploaded_by = db.relationship('User', backref='uploaded_versions')


# Association table for project assignments
project_assignments = db.Table(
    'project_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('projects.id'), primary_key=True)
)
