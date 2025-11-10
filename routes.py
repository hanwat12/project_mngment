import os
from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Project, Task, Comment, Document, UserPermission, Milestone, UserType, DocumentComment, DocumentVersion
from models_extensions import Outcome, ProjectApproval, TaskApproval, ManualTaskDependency

# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'Manager':
            return redirect(url_for('manager_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        manager_id = request.form.get('manager_id')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(username=username, email=email, role=role)
        if manager_id:
            user.manager_id = manager_id
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Set default permissions for non-admin users
        if role != 'Admin':
            default_permissions = [
                ('Proj', 'View'), ('Proj-team', 'View'), ('Proj doc', 'View'), 
                ('Proj Dis.', 'View'), ('task', 'View')
            ]
            for module, action in default_permissions:
                permission = UserPermission(user_id=user.id, module=module, action=action, granted=True)
                db.session.add(permission)
            db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    # Get managers for assignment
    managers = User.query.filter_by(role='Manager').all()
    return render_template('auth/register.html', managers=managers)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Dashboard routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        abort(403)
    
    # Get statistics
    total_projects = Project.query.count()
    active_projects = Project.query.filter(Project.status.in_(['Just Started', 'In Progress'])).count()
    completed_projects = Project.query.filter_by(status='Completed').count()
    
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(status='Completed').count()
    pending_tasks = Task.query.filter_by(status='Pending').count()
    overdue_tasks = Task.query.filter(Task.deadline < datetime.now().date(), Task.status != 'Completed').count()
    
    # Get pending approvals count
    pending_task_approvals = TaskApproval.query.filter_by(status='Pending').count()
    pending_project_approvals = ProjectApproval.query.filter_by(status='Pending').count()
    pending_approvals = pending_task_approvals + pending_project_approvals
    
    # Recent projects
    recent_projects = Project.query.order_by(Project.created_at.desc()).limit(3).all()
    
    # Upcoming deadlines
    upcoming_deadlines = Task.query.filter(
        Task.deadline >= datetime.now().date(),
        Task.status != 'Completed'
    ).order_by(Task.deadline.asc()).limit(5).all()
    
    return render_template('dashboard/admin.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         pending_approvals=pending_approvals,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Get accessible projects and tasks
    projects = current_user.get_accessible_projects()
    tasks = current_user.get_accessible_tasks()
    
    # Calculate statistics
    total_projects = len(projects)
    active_projects = len([p for p in projects if p.status in ['Just Started', 'In Progress']])
    completed_projects = len([p for p in projects if p.status == 'Completed'])
    
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == 'Completed'])
    pending_tasks = len([t for t in tasks if t.status == 'Pending'])
    overdue_tasks = len([t for t in tasks if t.is_overdue()])
    
    # Get pending approvals count for manager's team
    if current_user.role == 'Manager':
        # Get approvals for tasks/projects where manager has oversight
        team_user_ids = [u.id for u in current_user.managed_users]
        team_user_ids.append(current_user.id)  # Include manager's own items
        
        pending_task_approvals = TaskApproval.query.join(Task).filter(
            TaskApproval.status == 'Pending',
            Task.assigned_to_id.in_(team_user_ids)
        ).count()
        
        pending_project_approvals = ProjectApproval.query.join(Project).filter(
            ProjectApproval.status == 'Pending',
            Project.created_by_id.in_(team_user_ids)
        ).count()
    else:  # Admin
        pending_task_approvals = TaskApproval.query.filter_by(status='Pending').count()
        pending_project_approvals = ProjectApproval.query.filter_by(status='Pending').count()
    
    pending_approvals = pending_task_approvals + pending_project_approvals
    
    # Get total outcomes for accessible tasks
    from models_extensions import Outcome
    total_outcomes = 0
    for task in tasks:
        total_outcomes += Outcome.query.filter_by(task_id=task.id).count()
    
    # Recent projects and upcoming deadlines
    recent_projects = sorted(projects, key=lambda x: x.created_at, reverse=True)[:3]
    upcoming_deadlines = sorted([t for t in tasks if t.deadline and t.status != 'Completed'], 
                               key=lambda x: x.deadline)[:5]
    
    return render_template('dashboard/manager.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         pending_approvals=pending_approvals,
                         total_outcomes=total_outcomes,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Get accessible projects and tasks
    projects = current_user.get_accessible_projects()
    tasks = current_user.get_accessible_tasks()
    
    # Calculate statistics
    total_projects = len(projects)
    active_projects = len([p for p in projects if p.status in ['Just Started', 'In Progress']])
    completed_projects = len([p for p in projects if p.status == 'Completed'])
    
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == 'Completed'])
    pending_tasks = len([t for t in tasks if t.status == 'Pending'])
    overdue_tasks = len([t for t in tasks if t.is_overdue()])
    
    # Recent projects and upcoming deadlines
    recent_projects = sorted(projects, key=lambda x: x.created_at, reverse=True)[:3]
    upcoming_deadlines = sorted([t for t in tasks if t.deadline and t.status != 'Completed'], 
                               key=lambda x: x.deadline)[:5]
    
    return render_template('dashboard/user.html',
                         total_projects=total_projects,
                         active_projects=active_projects,
                         completed_projects=completed_projects,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         recent_projects=recent_projects,
                         upcoming_deadlines=upcoming_deadlines)

# Project routes
@app.route('/projects')
@login_required
def projects_list():
    projects = current_user.get_accessible_projects()
    return render_template('projects/list.html', projects=projects)

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline = request.form.get('deadline')
        assigned_users = request.form.getlist('assigned_users')
        
        project = Project(
            title=title,
            description=description,
            created_by_id=current_user.id
        )
        
        if deadline:
            project.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        
        db.session.add(project)
        db.session.flush()  # To get the project ID
        
        # Assign users to project
        for user_id in assigned_users:
            user = User.query.get(user_id)
            if user:
                project.assigned_users.append(user)
        
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('projects_list'))
    
    # Get users that can be assigned based on role
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('projects/create.html', assignable_users=assignable_users)

@app.route('/projects/<int:project_id>')
@login_required
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    tasks = project.tasks.all()
    comments = project.comments.order_by(Comment.created_at.desc()).all()
    documents = project.documents.all()
    
    return render_template('projects/view.html', 
                         project=project, 
                         tasks=tasks, 
                         comments=comments,
                         documents=documents)

@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] or \
       (current_user.role == 'Manager' and project.created_by_id != current_user.id):
        abort(403)
    
    if request.method == 'POST':
        project.title = request.form['title']
        project.description = request.form['description']
        project.status = request.form['status']
        deadline = request.form.get('deadline')
        
        if deadline:
            project.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        else:
            project.deadline = None
        
        # Update assigned users
        assigned_users = request.form.getlist('assigned_users')
        project.assigned_users.clear()
        for user_id in assigned_users:
            user = User.query.get(user_id)
            if user:
                project.assigned_users.append(user)
        
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('view_project', project_id=project.id))
    
    # Get users that can be assigned
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('projects/edit.html', 
                         project=project, 
                         assignable_users=assignable_users)

# Task routes
@app.route('/tasks')
@login_required
def tasks_list():
    tasks = current_user.get_accessible_tasks()
    
    # Get team members for reassignment dropdown
    if current_user.role == 'Admin':
        team_members = User.query.filter(User.id != current_user.id).all()
    elif current_user.role == 'Manager':
        # Manager can reassign to their managed users and other managers
        managed_user_ids = [u.id for u in current_user.managed_users]
        team_members = User.query.filter(
            db.or_(
                User.id.in_(managed_user_ids),
                User.role == 'Manager'
            ),
            User.id != current_user.id
        ).all()
    else:
        team_members = []
    
    return render_template('tasks/list.html', tasks=tasks, team_members=team_members)

@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        project_id = request.form['project_id']
        assigned_to_id = request.form.get('assigned_to_id')
        priority = request.form['priority']
        deadline = request.form.get('deadline')
        
        task = Task(
            title=title,
            description=description,
            project_id=project_id,
            created_by_id=current_user.id,
            priority=priority
        )
        
        if assigned_to_id:
            task.assigned_to_id = assigned_to_id
        
        if deadline:
            task.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        
        db.session.add(task)
        db.session.flush()  # Get task ID without committing
        
        # Handle task dependencies
        dependent_task_ids = request.form.getlist('dependent_on_task_id')
        for dep_task_id in dependent_task_ids:
            if dep_task_id:
                # Create dependency record if needed
                task.dependent_on_task_id = dep_task_id  # For backward compatibility
                break  # Use first one for the old field
        
        # Handle manual dependencies
        manual_deps = request.form.get('manual_dependencies', '').strip()
        if manual_deps:
            from models_extensions import ManualTaskDependency
            for dep_name in manual_deps.split(','):
                dep_name = dep_name.strip()
                if dep_name:
                    manual_dep = ManualTaskDependency(
                        task_id=task.id,
                        dependency_name=dep_name,
                        dependency_description=f"Manual dependency: {dep_name}"
                    )
                    db.session.add(manual_dep)
        
        db.session.commit()
        
        # Update project progress
        project = Project.query.get(project_id)
        project.update_progress()
        
        flash('Task created successfully with dependencies!', 'success')
        return redirect(url_for('tasks_list'))
    
    # Get accessible projects and assignable users
    projects = current_user.get_accessible_projects()
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('tasks/create.html', 
                         projects=projects, 
                         assignable_users=assignable_users)

@app.route('/tasks/<int:task_id>')
@login_required
def view_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    comments = task.comments.order_by(Comment.created_at.desc()).all()
    documents = task.documents.all()
    
    # Get available tasks for dependency modal
    accessible_projects = current_user.get_accessible_projects()
    available_tasks = []
    for project in accessible_projects:
        project_tasks = Task.query.filter_by(project_id=project.id).filter(Task.id != task.id).all()
        available_tasks.extend(project_tasks)
    
    return render_template('tasks/view.html', 
                         task=task, 
                         comments=comments,
                         documents=documents,
                         available_tasks=available_tasks)

@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] or \
       (current_user.role == 'Manager' and task.created_by_id != current_user.id):
        abort(403)
    
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        task.status = request.form['status']
        task.priority = request.form['priority']
        assigned_to_id = request.form.get('assigned_to_id')
        deadline = request.form.get('deadline')
        
        if assigned_to_id:
            task.assigned_to_id = assigned_to_id
        else:
            task.assigned_to_id = None
            
        if deadline:
            task.deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        else:
            task.deadline = None
        
        db.session.commit()
        
        # Update project progress
        task.project.update_progress()
        
        flash('Task updated successfully!', 'success')
        return redirect(url_for('view_task', task_id=task.id))
    
    # Get users that can be assigned
    if current_user.role == 'Admin':
        assignable_users = User.query.all()
    else:  # Manager
        assignable_users = current_user.managed_users.all()
    
    return render_template('tasks/edit.html', 
                         task=task, 
                         assignable_users=assignable_users)

@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user can mark this task as complete
    if task.assigned_to_id != current_user.id and current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Use approval workflow for non-admin users
    if current_user.role != 'Admin':
        task.mark_completed(current_user.id)
        flash('Task completion submitted for approval!', 'info')
    else:
        task.mark_completed()
        flash('Task marked as complete!', 'success')
    
    return redirect(url_for('view_task', task_id=task.id))

# Comment routes
@app.route('/projects/<int:project_id>/comment', methods=['POST'])
@login_required
def add_project_comment(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    content = request.form['content']
    comment = Comment(
        content=content,
        author_id=current_user.id,
        project_id=project_id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_project', project_id=project_id))

@app.route('/tasks/<int:task_id>/comment', methods=['POST'])
@login_required
def add_task_comment(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    content = request.form['content']
    comment = Comment(
        content=content,
        author_id=current_user.id,
        task_id=task_id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_task', task_id=task_id))

# Document upload routes
@app.route('/projects/<int:project_id>/upload', methods=['POST'])
@login_required
def upload_project_document(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('view_project', project_id=project_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('view_project', project_id=project_id))
    
    if file:
        filename = secure_filename(file.filename)
        # Add timestamp to avoid filename conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        document = Document(
            filename=filename,
            original_filename=file.filename,
            file_size=os.path.getsize(file_path),
            uploaded_by_id=current_user.id,
            project_id=project_id
        )
        
        db.session.add(document)
        db.session.commit()
        
        flash('Document uploaded successfully!', 'success')
    
    return redirect(url_for('view_project', project_id=project_id))

@app.route('/tasks/<int:task_id>/upload', methods=['POST'])
@login_required
def upload_task_document(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has access to this task
    accessible_tasks = current_user.get_accessible_tasks()
    if task not in accessible_tasks:
        abort(403)
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('view_task', task_id=task_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('view_task', task_id=task_id))
    
    if file:
        filename = secure_filename(file.filename)
        # Add timestamp to avoid filename conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        document = Document(
            filename=filename,
            original_filename=file.filename,
            file_size=os.path.getsize(file_path),
            uploaded_by_id=current_user.id,
            task_id=task_id
        )
        
        db.session.add(document)
        db.session.commit()
        
        flash('Document uploaded successfully!', 'success')
    
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if user has access to this document
    if document.project_id:
        accessible_projects = current_user.get_accessible_projects()
        if document.project not in accessible_projects:
            abort(403)
    elif document.task_id:
        accessible_tasks = current_user.get_accessible_tasks()
        if document.task not in accessible_tasks:
            abort(403)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], 
                             document.filename, 
                             as_attachment=True,
                             download_name=document.original_filename)

# Team management routes
@app.route('/team')
@login_required
def team_list():
    if current_user.role == 'Admin':
        users = User.query.all()
    elif current_user.role == 'Manager':
        users = current_user.managed_users.all()
    else:
        abort(403)
    
    return render_template('team/manage.html', users=users)

@app.route('/team/<int:user_id>/permissions', methods=['GET', 'POST'])
@login_required
def manage_permissions(user_id):
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Managers can only manage their own team members
    if current_user.role == 'Manager' and user.manager_id != current_user.id:
        abort(403)
    
    if request.method == 'POST':
        # Clear existing permissions
        UserPermission.query.filter_by(user_id=user.id).delete()
        
        # Add new permissions
        modules = ['Proj', 'Proj-team', 'Proj doc', 'Proj Dis.', 'task']
        actions = ['View', 'Add', 'Edit', 'Delete', 'Download']
        
        for module in modules:
            for action in actions:
                field_name = f"{module}_{action}".replace(' ', '_').replace('.', '_').replace('-', '_')
                if request.form.get(field_name):
                    permission = UserPermission(
                        user_id=user.id,
                        module=module,
                        action=action,
                        granted=True
                    )
                    db.session.add(permission)
        
        db.session.commit()
        flash('Permissions updated successfully!', 'success')
        return redirect(url_for('team_list'))
    
    # Get current permissions
    permissions = {}
    for perm in user.permissions:
        key = f"{perm.module}_{perm.action}".replace(' ', '_').replace('.', '_').replace('-', '_')
        permissions[key] = perm.granted
    
    return render_template('team/permissions.html', user=user, permissions=permissions)

# New routes for enhanced functionality
@app.route('/team/member/<int:user_id>')
@login_required
def team_member_detail(user_id):
    user = User.query.get_or_404(user_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if current_user.role == 'Manager':
        # Manager can only view their managed users or themselves
        managed_user_ids = [u.id for u in current_user.managed_users]
        managed_user_ids.append(current_user.id)
        if user_id not in managed_user_ids:
            abort(403)
    
    # Get user's tasks and projects
    user_tasks = Task.query.filter_by(assigned_to_id=user_id).all()
    user_projects = user.projects_assigned.all()
    
    # Calculate task statistics
    completed_tasks = [t for t in user_tasks if t.status == 'Completed']
    pending_tasks = [t for t in user_tasks if t.status in ['Pending', 'In Progress']]
    overdue_tasks = [t for t in user_tasks if t.is_overdue()]
    
    # Get pending approvals for this user
    pending_task_approvals = TaskApproval.query.join(Task).filter(
        TaskApproval.status == 'Pending',
        Task.assigned_to_id == user_id
    ).all()
    
    pending_project_approvals = ProjectApproval.query.join(Project).filter(
        ProjectApproval.status == 'Pending',
        Project.created_by_id == user_id
    ).all()
    
    pending_approvals = pending_task_approvals + pending_project_approvals
    
    return render_template('team/member_detail.html', 
                         user=user,
                         User=User,
                         user_tasks=user_tasks,
                         user_projects=user_projects,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         overdue_tasks=overdue_tasks,
                         pending_approvals=pending_approvals)

@app.route('/tasks/<int:task_id>/reassign', methods=['POST'])
@login_required
def reassign_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    new_assignee_id = request.form.get('new_assignee_id')
    if not new_assignee_id:
        flash('Please select a user to reassign the task to.', 'error')
        return redirect(request.referrer)
    
    new_assignee = User.query.get(new_assignee_id)
    if not new_assignee:
        flash('Selected user not found.', 'error')
        return redirect(request.referrer)
    
    # Calculate skill match based on user skills
    skill_match = 0
    if new_assignee.skills:
        import json
        try:
            user_skills = json.loads(new_assignee.skills)
            # Basic skill matching - you can enhance this logic
            task_keywords = task.title.lower().split()
            matches = sum(1 for skill in user_skills if any(keyword in skill.lower() for keyword in task_keywords))
            if user_skills:
                skill_match = int((matches / len(user_skills)) * 100)
        except:
            skill_match = 0
    
    # Store previous assignee for tracking
    task.reassigned_from_id = task.assigned_to_id
    task.assigned_to_id = new_assignee_id
    task.skill_match_percentage = skill_match
    
    db.session.commit()
    
    flash(f'Task reassigned to {new_assignee.username} successfully! (Skill match: {skill_match}%)', 'success')
    return redirect(request.referrer)

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check permissions
    if current_user.role != 'Admin' and project.created_by_id != current_user.id:
        abort(403)
    
    db.session.delete(project)
    db.session.commit()
    
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('projects_list'))

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] and task.created_by_id != current_user.id:
        abort(403)
    
    db.session.delete(task)
    db.session.commit()
    
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('tasks_list'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete yourself!', 'error')
        return redirect(url_for('team_list'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('team_list'))

@app.route('/settings')
@login_required
def settings():
    user_types = UserType.query.filter_by(is_active=True).all()
    # Check if user has permission to create users or manage user types
    can_add_user = current_user.has_permission('Settings', 'Add') or current_user.role == 'Admin'
    can_manage_permissions = current_user.has_permission('Settings', 'Edit') or current_user.role == 'Admin'
    return render_template('settings/index.html', 
                         user_types=user_types,
                         can_add_user=can_add_user,
                         can_manage_permissions=can_manage_permissions)

@app.route('/settings/user-types/create', methods=['GET', 'POST'])
@login_required
def create_user_type():
    # Check if user has permission to create user types
    if not current_user.has_permission('Settings', 'Add'):
        abort(403)
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        
        user_type = UserType(
            name=name,
            description=description,
            created_by_id=current_user.id
        )
        
        db.session.add(user_type)
        db.session.commit()
        
        flash('User type created successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings/create_user_type.html')

@app.route('/your-permissions')
@login_required
def your_permissions():
    """Show user's own permissions"""
    permissions = {}
    for perm in current_user.permissions:
        module_key = perm.module.replace(' ', '_').replace('.', '_').replace('-', '_')
        if module_key not in permissions:
            permissions[module_key] = {}
        permissions[module_key][perm.action] = perm.granted
    
    return render_template('settings/your_permissions.html', permissions=permissions)

@app.route('/manage-skills', methods=['GET', 'POST'])
@login_required
def manage_skills():
    """Manage user's skills"""
    if request.method == 'POST':
        skills = request.form.getlist('skills[]')
        import json
        current_user.skills = json.dumps(skills)
        db.session.commit()
        flash('Skills updated successfully!', 'success')
        return redirect(url_for('manage_skills'))
    
    # Get current skills
    current_skills = []
    if current_user.skills:
        import json
        try:
            current_skills = json.loads(current_user.skills)
        except:
            current_skills = []
    
    return render_template('settings/manage_skills.html', current_skills=current_skills)

# Fix milestone routes
@app.route('/projects/<int:project_id>/milestones', methods=['GET'])
@login_required
def project_milestones(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check access
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    milestones = Milestone.query.filter_by(project_id=project_id).order_by(Milestone.created_at).all()
    
    return render_template('projects/milestones.html', project=project, milestones=milestones)

@app.route('/projects/<int:project_id>/milestones/create', methods=['GET', 'POST'])
@login_required  
def create_milestone(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        due_date_str = request.form.get('due_date')
        
        due_date = None
        if due_date_str:
            from datetime import datetime
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        
        milestone = Milestone(
            title=title,
            description=description,
            due_date=due_date,
            project_id=project_id
        )
        
        db.session.add(milestone)
        db.session.commit()
        
        flash('Milestone created successfully!', 'success')
        return redirect(url_for('view_project', project_id=project_id))
    
    return render_template('projects/create_milestone.html', project=project)

@app.route('/milestones/<int:milestone_id>/complete', methods=['POST'])
@login_required
def complete_milestone_action(milestone_id):
    milestone = Milestone.query.get_or_404(milestone_id)
    
    # Check access
    accessible_projects = current_user.get_accessible_projects()
    if milestone.project not in accessible_projects:
        abort(403)
    
    milestone.status = 'Completed'
    db.session.commit()
    
    flash('Milestone marked as complete!', 'success')
    return redirect(request.referrer)

@app.route('/settings/add-user', methods=['GET', 'POST'])
@login_required
def settings_add_user():
    """Add user from settings if permission granted"""
    if not (current_user.has_permission('Settings', 'Add') or current_user.role in ['Admin', 'Manager']):
        abort(403)
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        manager_id = request.form.get('manager_id')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('settings/add_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('settings/add_user.html')
        
        user = User(
            username=username,
            email=email,
            role=role,
            manager_id=manager_id if manager_id else None
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('settings'))
    
    # Get available managers and user types
    managers = User.query.filter_by(role='Manager').all()
    user_types = UserType.query.filter_by(is_active=True).all()
    return render_template('settings/add_user.html', managers=managers, user_types=user_types)

@app.route('/api/dashboard/<task_type>')
@login_required
def api_dashboard_tasks(task_type):
    """API endpoint for dashboard task modals"""
    from datetime import date
    from flask import jsonify
    
    # Get user's accessible tasks and projects
    accessible_tasks = current_user.get_accessible_tasks()
    accessible_projects = current_user.get_accessible_projects()
    
    if task_type == 'completed_tasks':
        tasks = [task for task in accessible_tasks if task.status == 'Completed']
        tasks = sorted(tasks, key=lambda x: x.completed_at or x.updated_at, reverse=True)[:50]
    elif task_type == 'active_tasks':
        tasks = [task for task in accessible_tasks if task.status in ['Pending', 'In Progress']]
        tasks = sorted(tasks, key=lambda x: x.created_at, reverse=True)[:50]
    elif task_type == 'overdue_tasks':
        today = date.today()
        tasks = [task for task in accessible_tasks if task.deadline and task.deadline < today and task.status != 'Completed']
        tasks = sorted(tasks, key=lambda x: x.deadline)[:50]
    elif task_type == 'active_projects':
        projects = [project for project in accessible_projects if project.status in ['Just Started', 'In Progress']]
        projects = sorted(projects, key=lambda x: x.created_at, reverse=True)[:50]
        
        project_data = []
        for project in projects:
            project_data.append({
                'id': project.id,
                'title': project.title,
                'description': project.description[:100] + '...' if project.description and len(project.description) > 100 else project.description,
                'status': project.status,
                'progress': project.progress,
                'created_by': project.creator.username,
                'created_at': project.created_at.strftime('%b %d, %Y'),
                'deadline': project.deadline.strftime('%b %d, %Y') if project.deadline else None,
                'tasks_count': project.tasks.count(),
                'team_count': len(project.assigned_users)
            })
        return jsonify({'projects': project_data})
    elif task_type == 'task_outcomes':
        from models_extensions import Outcome
        # Get outcomes for accessible tasks
        task_ids = [task.id for task in accessible_tasks]
        if task_ids:
            outcomes = Outcome.query.filter(Outcome.task_id.in_(task_ids)).order_by(Outcome.created_at.desc()).limit(50).all()
        else:
            outcomes = []
        
        outcome_data = []
        for outcome in outcomes:
            outcome_data.append({
                'id': outcome.id,
                'title': outcome.title,
                'task_title': outcome.task.title,
                'task_id': outcome.task.id,
                'status': outcome.status,
                'deadline': outcome.deadline.strftime('%b %d, %Y') if outcome.deadline else None,
                'created_by': outcome.created_by.username
            })
        return jsonify({'outcomes': outcome_data})
    elif task_type == 'pending_approvals':
        pending_data = []
        
        # Get accessible task and project IDs
        accessible_task_ids = [task.id for task in accessible_tasks]
        accessible_project_ids = [project.id for project in accessible_projects]
        
        # Task approvals for accessible tasks
        from models_extensions import TaskApproval, ProjectApproval
        if accessible_task_ids:
            task_approvals = TaskApproval.query.filter(
                TaskApproval.status == 'Pending',
                TaskApproval.task_id.in_(accessible_task_ids)
            ).all()
            
            for approval in task_approvals:
                pending_data.append({
                    'id': approval.task.id,
                    'type': 'task',
                    'title': approval.task.title,
                    'project_title': approval.task.project.title,
                    'marked_by': approval.marked_complete_by.username,
                    'marked_at': approval.marked_complete_at.strftime('%b %d, %Y at %I:%M %p'),
                    'priority': approval.task.priority,
                    'status': approval.task.status
                })
        
        # Project approvals for accessible projects
        if accessible_project_ids:
            project_approvals = ProjectApproval.query.filter(
                ProjectApproval.status == 'Pending',
                ProjectApproval.project_id.in_(accessible_project_ids)
            ).all()
            
            for approval in project_approvals:
                pending_data.append({
                    'id': approval.project.id,
                    'type': 'project',
                    'title': approval.project.title,
                    'marked_by': approval.marked_complete_by.username,
                    'marked_at': approval.marked_complete_at.strftime('%b %d, %Y at %I:%M %p'),
                    'priority': 'N/A',
                    'status': approval.project.status
                })
        
        return jsonify({'items': pending_data})
    else:
        tasks = []
    
    task_data = []
    for task in tasks:
        task_data.append({
            'id': task.id,
            'title': task.title,
            'project_title': task.project.title,
            'priority': task.priority,
            'status': task.status,
            'assigned_user': task.assigned_user.username if task.assigned_user else None,
            'deadline': task.deadline.strftime('%b %d, %Y') if task.deadline else None,
            'created_by': task.creator.username,
            'created_at': task.created_at.strftime('%b %d, %Y')
        })
    
    return jsonify({'tasks': task_data})

@app.route('/documents/<int:document_id>/comments', methods=['POST'])
@login_required
def add_document_comment(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check access to document
    if document.project_id:
        accessible_projects = current_user.get_accessible_projects()
        if document.project not in accessible_projects:
            abort(403)
    elif document.task_id:
        accessible_tasks = current_user.get_accessible_tasks()
        if document.task not in accessible_tasks:
            abort(403)
    
    content = request.form['content']
    comment = DocumentComment(
        content=content,
        document_id=document_id,
        author_id=current_user.id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully!', 'success')
    
    # Redirect back to the appropriate view
    if document.project_id:
        return redirect(url_for('view_project', project_id=document.project_id))
    else:
        return redirect(url_for('view_task', task_id=document.task_id))

# API endpoints for dynamic data loading
@app.route('/api/project/<int:project_id>/tasks')
@login_required
def api_project_tasks(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check access
    accessible_projects = current_user.get_accessible_projects()
    if project not in accessible_projects:
        abort(403)
    
    # Get all tasks from user's accessible projects for dependency selection
    all_tasks = []
    for accessible_project in accessible_projects:
        project_tasks = Task.query.filter_by(project_id=accessible_project.id).all()
        for task in project_tasks:
            all_tasks.append({
                'id': task.id, 
                'title': f"{task.title} ({accessible_project.title})",
                'project_title': accessible_project.title
            })
    
    return {
        'tasks': all_tasks,
        'project_deadline': project.deadline.strftime('%Y-%m-%d') if project.deadline else None
    }

@app.route('/api/tasks/all')
@login_required
def api_all_tasks():
    """Get all accessible tasks for dependency dropdowns"""
    accessible_projects = current_user.get_accessible_projects()
    all_tasks = []
    
    for project in accessible_projects:
        project_tasks = Task.query.filter_by(project_id=project.id).all()
        for task in project_tasks:
            all_tasks.append({
                'id': task.id,
                'title': task.title,
                'project_title': project.title,
                'status': task.status
            })
    
    return {'tasks': all_tasks}

# Routes for outcomes and additional features

@app.route('/tasks/<int:task_id>/outcomes/create', methods=['POST'])
@login_required
def create_outcome(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager'] and current_user.id != task.assigned_to_id:
        abort(403)
    
    title = request.form['title']
    description = request.form.get('description', '')
    deadline_str = request.form.get('deadline')
    
    deadline = None
    if deadline_str:
        from datetime import datetime
        deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
    
    outcome = Outcome(
        title=title,
        description=description,
        deadline=deadline,
        task_id=task_id,
        created_by_id=current_user.id
    )
    
    db.session.add(outcome)
    db.session.commit()
    
    flash('Outcome created successfully!', 'success')
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/outcomes/<int:outcome_id>/complete', methods=['POST'])
@login_required
def complete_outcome(outcome_id):
    outcome = Outcome.query.get_or_404(outcome_id)
    
    # Check if user is assigned to the task
    if current_user.id != outcome.task.assigned_to_id and current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    outcome.mark_completed(current_user.id)
    
    flash('Outcome marked as complete!', 'success')
    return redirect(request.referrer)

# Approval workflow routes
@app.route('/tasks/<int:task_id>/approve', methods=['POST'])
@login_required
def approve_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has authority to approve
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Find pending approval
    approval = TaskApproval.query.filter_by(task_id=task_id, status='Pending').first()
    if approval:
        approval.status = 'Approved'
        approval.approved_by_id = current_user.id
        approval.approved_at = datetime.now(timezone.utc)
        
        task.status = 'Completed'
        task.completed_at = datetime.now(timezone.utc)
        
        db.session.commit()
        flash('Task approved and marked as complete!', 'success')
    
    return redirect(request.referrer)

@app.route('/tasks/<int:task_id>/reject', methods=['POST'])
@login_required
def reject_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check if user has authority to reject
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Find pending approval
    approval = TaskApproval.query.filter_by(task_id=task_id, status='Pending').first()
    if approval:
        approval.status = 'Rejected'
        approval.approved_by_id = current_user.id
        approval.approved_at = datetime.now(timezone.utc)
        
        task.status = 'In Progress'  # Reset to in progress
        
        db.session.commit()
        flash('Task completion rejected. Task returned to in progress.', 'warning')
    
    return redirect(request.referrer)

@app.route('/projects/<int:project_id>/approve', methods=['POST'])
@login_required
def approve_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has authority to approve
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    # Find pending approval
    approval = ProjectApproval.query.filter_by(project_id=project_id, status='Pending').first()
    if approval:
        approval.status = 'Approved'
        approval.approved_by_id = current_user.id
        approval.approved_at = datetime.now(timezone.utc)
        
        project.status = 'Completed'
        
        db.session.commit()
        flash('Project approved and marked as complete!', 'success')
    
    return redirect(request.referrer)
    
    current_skills = []
    if current_user.skills:
        import json
        try:
            current_skills = json.loads(current_user.skills)
        except:
            current_skills = []
    
    return render_template('profile/skills.html', current_skills=current_skills)

@app.route('/tasks/<int:task_id>/add_manual_dependency', methods=['POST'])
@login_required
def add_manual_dependency(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Check permissions
    if current_user.role not in ['Admin', 'Manager']:
        abort(403)
    
    dependency_type = request.form.get('dependency_type')
    
    if dependency_type == 'task':
        dependent_task_id = request.form.get('dependent_task_id')
        if dependent_task_id:
            dependent_task = Task.query.get(dependent_task_id)
            if dependent_task:
                # Update the task's dependent_on_task_id field directly
                task.dependent_on_task_id = dependent_task_id
                db.session.commit()
                flash('Task dependency added successfully!', 'success')
    elif dependency_type == 'manual':
        dependency_name = request.form.get('dependency_name')
        dependency_description = request.form.get('dependency_description', '')
        if dependency_name:
            manual_dep = ManualTaskDependency(
                task_id=task_id,
                dependency_name=dependency_name,
                dependency_description=dependency_description
            )
            db.session.add(manual_dep)
            db.session.commit()
            flash('Manual dependency added successfully!', 'success')
    
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/api/team_members')
@login_required
def api_team_members():
    """API endpoint to get team members for dropdowns"""
    from flask import jsonify
    
    if current_user.role == 'Admin':
        users = User.query.filter(User.id != current_user.id).all()
    elif current_user.role == 'Manager':
        # Manager can reassign to their managed users and other managers
        managed_user_ids = [u.id for u in current_user.managed_users]
        users = User.query.filter(
            db.or_(
                User.id.in_(managed_user_ids),
                User.role == 'Manager'
            ),
            User.id != current_user.id
        ).all()
    else:
        users = []
    
    team_data = [{'id': user.id, 'username': user.username, 'role': user.role} for user in users]
    return jsonify({'team_members': team_data})

@app.route('/api/task_outcomes')
@login_required
def api_task_outcomes():
    """API endpoint to get task outcomes for dashboard modal"""
    from models_extensions import Outcome
    accessible_tasks = current_user.get_accessible_tasks()
    
    tasks_with_outcomes = []
    for task in accessible_tasks:
        outcomes = Outcome.query.filter_by(task_id=task.id).all()
        if outcomes:
            task_data = {
                'id': task.id,
                'title': task.title,
                'project_title': task.project.title,
                'progress': task.get_progress_percentage(),
                'outcomes': [{
                    'id': outcome.id,
                    'title': outcome.title,
                    'status': outcome.status,
                    'deadline': outcome.deadline.strftime('%Y-%m-%d') if outcome.deadline else None,
                    'is_overdue': outcome.is_overdue() if outcome.deadline else False
                } for outcome in outcomes]
            }
            tasks_with_outcomes.append(task_data)
    
    return {'tasks': tasks_with_outcomes}

@app.route('/api/task-outcomes/<int:task_id>')
@login_required
def api_specific_task_outcomes(task_id):
    """API endpoint to get outcomes for a specific task"""
    from flask import jsonify
    from models_extensions import Outcome
    
    # Check if user has access to this task
    task = Task.query.get_or_404(task_id)
    accessible_tasks = current_user.get_accessible_tasks()
    task_ids = [t.id for t in accessible_tasks]
    
    if task_id not in task_ids:
        return jsonify({'error': 'Access denied'}), 403
    
    outcomes = Outcome.query.filter_by(task_id=task_id).order_by(Outcome.created_at.desc()).all()
    
    outcome_data = []
    for outcome in outcomes:
        outcome_data.append({
            'id': outcome.id,
            'title': outcome.title,
            'description': outcome.description,
            'status': outcome.status,
            'deadline': outcome.deadline.strftime('%b %d, %Y') if outcome.deadline else None,
            'created_by': outcome.created_by.username,
            'created_at': outcome.created_at.strftime('%b %d, %Y'),
            'completed_at': outcome.completed_at.strftime('%b %d, %Y') if outcome.completed_at else None
        })
    
    return jsonify({'outcomes': outcome_data})

# API endpoints for dashboard modals
@app.route('/api/dashboard/<task_type>')
@login_required
def api_dashboard_data(task_type):
    """API endpoint for dashboard task modals"""
    from flask import jsonify
    
    try:
        # Get accessible tasks based on user role
        accessible_tasks = current_user.get_accessible_tasks()
        
        if task_type == 'completed_tasks':
            tasks = [task for task in accessible_tasks if task.status == 'Completed']
        elif task_type == 'active_tasks' or task_type == 'pending_tasks':
            tasks = [task for task in accessible_tasks if task.status in ['Pending', 'In Progress']]
        elif task_type == 'overdue_tasks':
            tasks = [task for task in accessible_tasks if task.is_overdue() and task.status != 'Completed']
        elif task_type == 'pending_approvals':
            # Get pending approvals based on user role
            if current_user.role == 'Admin':
                # Admin sees all pending approvals
                task_approvals = TaskApproval.query.filter_by(status='Pending').all()
                project_approvals = ProjectApproval.query.filter_by(status='Pending').all()
            elif current_user.role == 'Manager':
                # Manager sees approvals for their team
                team_user_ids = [u.id for u in current_user.managed_users]
                team_user_ids.append(current_user.id)
                
                task_approvals = TaskApproval.query.join(Task).filter(
                    TaskApproval.status == 'Pending',
                    Task.assigned_to_id.in_(team_user_ids)
                ).all()
                
                project_approvals = ProjectApproval.query.join(Project).filter(
                    ProjectApproval.status == 'Pending',
                    Project.created_by_id.in_(team_user_ids)
                ).all()
            else:
                task_approvals = []
                project_approvals = []
            
            # Combine approvals into task format
            approval_items = []
            for approval in task_approvals:
                approval_items.append({
                    'id': approval.task_id,
                    'title': approval.task.title,
                    'project_title': approval.task.project.title,
                    'priority': approval.task.priority,
                    'status': 'Pending Approval',
                    'assigned_user': approval.marked_complete_by.username if approval.marked_complete_by else None,
                    'deadline': approval.task.deadline.strftime('%b %d, %Y') if approval.task.deadline else None,
                    'type': 'task'
                })
            
            for approval in project_approvals:
                approval_items.append({
                    'id': approval.project_id,
                    'title': approval.project.title,
                    'project_title': approval.project.title,
                    'priority': 'Medium',
                    'status': 'Pending Approval',
                    'assigned_user': approval.marked_complete_by.username if approval.marked_complete_by else None,
                    'deadline': approval.project.deadline.strftime('%b %d, %Y') if approval.project.deadline else None,
                    'type': 'project'
                })
            
            return jsonify({'tasks': approval_items})
        else:
            # Format task data for JSON response
            task_data = []
            for task in tasks:
                task_data.append({
                    'id': task.id,
                    'title': task.title,
                    'project_title': task.project.title,
                    'priority': task.priority,
                    'status': task.status,
                    'assigned_user': task.assigned_user.username if task.assigned_user else None,
                    'deadline': task.deadline.strftime('%b %d, %Y') if task.deadline else None,
                    'type': 'task'
                })
            
            return jsonify({'tasks': task_data})
        
    except Exception as e:
        return jsonify({'error': str(e), 'tasks': []})

# API endpoints for approval functionality
@app.route('/api/approve/<item_type>/<int:item_id>', methods=['POST'])
@login_required
def api_approve_item(item_type, item_id):
    """API endpoint to approve tasks/projects"""
    from flask import jsonify
    
    try:
        if current_user.role not in ['Admin', 'Manager']:
            return jsonify({'success': False, 'message': 'Insufficient permissions'})
        
        if item_type == 'task':
            approval = TaskApproval.query.filter_by(task_id=item_id, status='Pending').first()
            if approval:
                approval.status = 'Approved'
                approval.approved_by_id = current_user.id
                approval.approved_at = datetime.now()
                
                # Update task status to completed
                task = Task.query.get(item_id)
                if task:
                    task.status = 'Completed'
                    task.completed_at = datetime.now()
                    task.project.update_progress()
                
                db.session.commit()
                return jsonify({'success': True, 'message': 'Task approved successfully'})
            
        elif item_type == 'project':
            approval = ProjectApproval.query.filter_by(project_id=item_id, status='Pending').first()
            if approval:
                approval.status = 'Approved'
                approval.approved_by_id = current_user.id
                approval.approved_at = datetime.now()
                
                # Update project status to completed
                project = Project.query.get(item_id)
                if project:
                    project.status = 'Completed'
                
                db.session.commit()
                return jsonify({'success': True, 'message': 'Project approved successfully'})
        
        return jsonify({'success': False, 'message': 'Approval not found'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/reject/<item_type>/<int:item_id>', methods=['POST'])
@login_required
def api_reject_item(item_type, item_id):
    """API endpoint to reject tasks/projects (mark as not complete)"""
    from flask import jsonify
    
    try:
        if current_user.role not in ['Admin', 'Manager']:
            return jsonify({'success': False, 'message': 'Insufficient permissions'})
        
        if item_type == 'task':
            approval = TaskApproval.query.filter_by(task_id=item_id, status='Pending').first()
            if approval:
                approval.status = 'Rejected'
                approval.approved_by_id = current_user.id
                approval.approved_at = datetime.now()
                
                # Update task status back to active
                task = Task.query.get(item_id)
                if task:
                    task.status = 'Pending'
                    task.completed_at = None
                    task.project.update_progress()
                
                db.session.commit()
                return jsonify({'success': True, 'message': 'Task marked as not complete'})
            
        elif item_type == 'project':
            approval = ProjectApproval.query.filter_by(project_id=item_id, status='Pending').first()
            if approval:
                approval.status = 'Rejected'
                approval.approved_by_id = current_user.id
                approval.approved_at = datetime.now()
                
                # Update project status back to active
                project = Project.query.get(item_id)
                if project:
                    project.status = 'In Progress'
                
                db.session.commit()
                return jsonify({'success': True, 'message': 'Project marked as not complete'})
        
        return jsonify({'success': False, 'message': 'Approval not found'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/milestones/<int:milestone_id>/complete', methods=['POST'])
@login_required
def complete_milestone_api(milestone_id):
    """API endpoint to mark milestone as complete"""
    from flask import jsonify
    try:
        milestone = Milestone.query.get_or_404(milestone_id)
        milestone.status = "Completed"
        db.session.commit()
        return jsonify({'success': True, 'message': 'Milestone completed successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
