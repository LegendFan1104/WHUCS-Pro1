from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import bcrypt
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456@127.0.0.1/appointment_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(16)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'
login_manager.login_message = '请登录以访问此页面。'
login_manager.login_message_category = 'info'  # 设置消息类别为 'info'


# 自定义装饰器：检查用户角色
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                flash('权限不足', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# 模型定义
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # user/provider/admin
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True)
    appointments = db.relationship('Appointment', backref='user', lazy=True)
    services = db.relationship('Service', backref='provider', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # 分钟
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    available_slots = db.relationship('AvailableSlot', backref='service', lazy=True)
    appointments = db.relationship('Appointment', backref='service', lazy=True)


class AvailableSlot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_booked = db.Column(db.Boolean, default=False)
    appointment = db.relationship('Appointment', backref='slot', uselist=False)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    slot_id = db.Column(db.Integer, db.ForeignKey('available_slot.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending/confirmed/canceled/completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    feedback = db.relationship('Feedback', backref='appointment', uselist=False)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# 用户认证相关路由
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        data = request.form
        if not all([data.get('username'), data.get('email'), data.get('password'), data.get('phone')]):
            flash('请填写所有必填字段', 'error')
            return redirect(url_for('user_register'))

        if User.query.filter_by(username=data['username']).first():
            flash('用户名已存在', 'error')
            return redirect(url_for('user_register'))

        if User.query.filter_by(email=data['email']).first():
            flash('邮箱已被注册', 'error')
            return redirect(url_for('user_register'))

        user = User(
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            role='user'
        )
        user.set_password(data['password'])

        try:
            db.session.add(user)
            db.session.commit()
            flash('注册成功，请登录', 'success')
            return redirect(url_for('user_login'))
        except Exception as e:
            db.session.rollback()
            flash(f'注册失败: {str(e)}', 'error')
            return redirect(url_for('user_register'))

    return render_template('user_register.html')


@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('请输入用户名和密码', 'error')
            return redirect(url_for('user_login'))

        # 只查询角色为 'user' 的用户
        user = User.query.filter_by(username=username, role='user').first()
        if user and user.check_password(password):
            login_user(user)
            flash('登录成功', 'success')
            return redirect(url_for('home'))

        flash('用户名或密码错误', 'error')

    return render_template('user_login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已成功登出', 'success')
    return redirect(url_for('home'))


# 服务提供者相关路由
@app.route('/provider/register', methods=['GET', 'POST'])
def provider_register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        data = request.form
        if not all([data.get('username'), data.get('email'), data.get('password'), data.get('phone')]):
            flash('请填写所有必填字段', 'error')
            return redirect(url_for('provider_register'))

        if User.query.filter_by(username=data['username']).first():
            flash('用户名已存在', 'error')
            return redirect(url_for('provider_register'))

        if User.query.filter_by(email=data['email']).first():
            flash('邮箱已被注册', 'error')
            return redirect(url_for('provider_register'))

        user = User(
            username=data['username'],
            email=data['email'],
            phone=data['phone'],
            role='provider'
        )
        user.set_password(data['password'])

        try:
            db.session.add(user)
            db.session.commit()
            flash('注册成功，请登录', 'success')
            return redirect(url_for('provider_login'))  # 修改为 provider_login
        except Exception as e:
            db.session.rollback()
            flash(f'注册失败: {str(e)}', 'error')
            return redirect(url_for('provider_register'))

    return render_template('provider_register.html')


@app.route('/provider/dashboard')
@login_required
@role_required('provider')
def provider_dashboard():
    services = Service.query.filter_by(provider_id=current_user.id).all()
    upcoming_slots = AvailableSlot.query.join(Service).filter(
        Service.provider_id == current_user.id,
        AvailableSlot.start_time > datetime.utcnow(),
        AvailableSlot.is_booked == False
    ).order_by(AvailableSlot.start_time).limit(5).all()

    upcoming_appointments = Appointment.query.join(AvailableSlot).join(Service).filter(
        Service.provider_id == current_user.id,
        AvailableSlot.start_time > datetime.utcnow(),
        Appointment.status.in_(['pending', 'confirmed'])
    ).order_by(AvailableSlot.start_time).limit(5).all()

    return render_template('provider_dashboard.html',
                           services=services,
                           upcoming_slots=upcoming_slots,
                           upcoming_appointments=upcoming_appointments)


@app.route('/provider/service/add', methods=['GET', 'POST'])
@login_required
@role_required('provider')
def add_service():
    if request.method == 'POST':
        data = request.form

        if not all([data.get('name'), data.get('description'), data.get('price'), data.get('duration'), data.get('start_time')]):
            flash('请填写所有必填字段', 'error')
            return redirect(url_for('add_service'))

        try:
            price = float(data['price'])
            duration = int(data['duration'])
            start_time = datetime.fromisoformat(data['start_time'])
            end_time = start_time + timedelta(minutes=duration)
        except ValueError:
            flash('输入的数据格式不正确，请检查价格、时长和开始时间', 'error')
            return redirect(url_for('add_service'))

        new_service = Service(
            name=data['name'],
            description=data['description'],
            price=price,
            duration=duration,
            provider_id=current_user.id
        )

        try:
            db.session.add(new_service)
            db.session.commit()
            flash('服务添加成功', 'success')
            return redirect(url_for('provider_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'添加服务时出错: {str(e)}', 'error')
            return redirect(url_for('add_service'))

    return render_template('add_service.html')


@app.route('/provider/service/<int:service_id>/add_slot', methods=['GET', 'POST'])
@login_required
@role_required('provider')
def add_service_slot(service_id):
    service = Service.query.get(service_id)
    if not service:
        flash('服务不存在', 'error')
        return redirect(url_for('provider_dashboard'))

    if request.method == 'POST':
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')

        try:
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
        except ValueError:
            flash('日期和时间格式不正确', 'error')
            return redirect(url_for('add_service_slot', service_id=service_id))

        if end_time <= start_time:
            flash('结束时间必须晚于开始时间', 'error')
            return redirect(url_for('add_service_slot', service_id=service_id))

        slot = AvailableSlot(
            service_id=service_id,
            start_time=start_time,
            end_time=end_time
        )

        try:
            db.session.add(slot)
            db.session.commit()
            flash('服务时段添加成功', 'success')
            return redirect(url_for('provider_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'添加服务时段失败: {str(e)}', 'error')
            return redirect(url_for('add_service_slot', service_id=service_id))

    return render_template('add_service_slot.html', service=service)


@app.route('/service/<int:service_id>/details')
@login_required
def service_details(service_id):
    service = Service.query.get(service_id)
    if not service:
        flash('服务不存在', 'error')
        return redirect(url_for('home'))

    provider = User.query.get(service.provider_id)
    available_slots = AvailableSlot.query.filter_by(service_id=service_id, is_booked=False).all()

    return render_template('service_details.html', service=service, provider=provider, available_slots=available_slots)


@app.route('/book_appointment', methods=['POST'])
@login_required
def book_appointment():
    service_id = request.form.get('service_id')
    slot_id = request.form.get('slot_id')

    if not service_id or not slot_id:
        flash('请选择服务和时段', 'error')
        return redirect(url_for('home'))

    service = Service.query.get(service_id)
    slot = AvailableSlot.query.get(slot_id)

    if not service or not slot:
        flash('服务或时段不存在', 'error')
        return redirect(url_for('home'))

    if slot.is_booked:
        flash('该时段已被预订', 'error')
        return redirect(url_for('service_details', service_id=service_id))

    appointment = Appointment(
        user_id=current_user.id,
        service_id=service_id,
        slot_id=slot_id
    )

    try:
        slot.is_booked = True
        db.session.add(appointment)
        db.session.commit()
        flash('预约成功', 'success')
        return redirect(url_for('user_appointments'))
    except Exception as e:
        db.session.rollback()
        flash(f'预约失败: {str(e)}', 'error')
        return redirect(url_for('service_details', service_id=service_id))


@app.route('/')
def home():
    services = Service.query.all()
    return render_template('home.html', services=services)


@app.route('/user_appointments')
@login_required
def user_appointments():
    appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    return render_template('user_appointments.html', appointments=appointments)


@app.route('/search_services', methods=['GET'])
@login_required
def search_services():
    keyword = request.args.get('keyword', '')
    if keyword:
        services = Service.query.filter(Service.name.contains(keyword)).all()
    else:
        services = Service.query.all()
    return render_template('search_results.html', services=services)


@app.route('/provider/login', methods=['GET', 'POST'])
def provider_login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('请输入用户名和密码', 'error')
            return redirect(url_for('provider_login'))

        # 只查询角色为 'provider' 的用户
        user = User.query.filter_by(username=username, role='provider').first()
        if user and user.check_password(password):
            login_user(user)
            flash('登录成功', 'success')
            return redirect(url_for('provider_dashboard'))

        flash('用户名或密码错误', 'error')

    return render_template('provider_login.html')


# 服务商批准预约
@app.route('/provider/appointment/<int:appointment_id>/approve', methods=['POST'])
@login_required
@role_required('provider')
def approve_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.service.provider_id == current_user.id:
        appointment.status = 'confirmed'
        try:
            db.session.commit()
            flash('预约已批准', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'批准预约失败: {str(e)}', 'error')
    else:
        flash('你无权批准此预约', 'error')
    return redirect(url_for('provider_dashboard'))


# 服务商拒绝预约
@app.route('/provider/appointment/<int:appointment_id>/reject', methods=['POST'])
@login_required
@role_required('provider')
def reject_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.service.provider_id == current_user.id:
        appointment.status = 'canceled'
        appointment.slot.is_booked = False  # 释放该时段
        try:
            db.session.commit()
            flash('预约已拒绝', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'拒绝预约失败: {str(e)}', 'error')
    else:
        flash('你无权拒绝此预约', 'error')
    return redirect(url_for('provider_dashboard'))


@app.route('/provider/service/cancel/<int:service_id>', methods=['POST'])
@login_required
@role_required('provider')
def cancel_service(service_id):
    service = Service.query.get_or_404(service_id)
    if service.provider_id != current_user.id:
        flash('你没有权限取消此服务', 'error')
        return redirect(url_for('provider_dashboard'))
    try:
        # 先删关联的预约
        Appointment.query.filter_by(service_id=service_id).delete()
        # 再删关联的可用时段
        AvailableSlot.query.filter_by(service_id=service_id).delete()
        # 最后删服务
        db.session.delete(service)
        db.session.commit()
        flash('服务已成功取消', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'取消服务时出错: {str(e)}', 'error')
    return redirect(url_for('provider_dashboard'))



if __name__ == '__main__':
    app.run(debug=True)