from flask import Blueprint, render_template, url_for, flash, redirect, request, session
from app.__init__ import db, bcrypt
from app.forms import RegistrationForm, LoginForm, SentimentForm
from app.models import User, Input
from flask_login import login_user, current_user, logout_user, login_required
import pickle

main = Blueprint('main', __name__)

@main.route('/')
def index():
    """Homepage route."""
    return render_template('index.html')


# Load the model
model = pickle.load(open('app/svm_model.pkl', 'rb'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.analyze'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.analyze'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('main.analyze'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    form = SentimentForm()
    if form.validate_on_submit():
        text = form.input_text.data
        sentiment = model.predict([text])[0]
        new_input = Input(user_id=current_user.id, input_text=text, predicted_sentiment=sentiment)
        db.session.add(new_input)
        db.session.commit()
        return render_template('result.html', sentiment=sentiment)
    return render_template('analyze.html', form=form)


@main.route('/sentiment', methods=['GET', 'POST'])
def sentiment():
    """Route to handle sentiment analysis input."""
    if not session.get('user'):  # Ensure user is authenticated
        flash("You must be logged in to access this page.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        text_input = request.form.get('text_input')  # Get the text from the form
        if text_input.strip():
            # Predict sentiment using the trained model
            sentiment_label = predict_sentiment(text_input)
            return redirect(url_for('result', sentiment=sentiment_label))
        else:
            flash("Please enter valid text for analysis.")
    return render_template('sentiment.html')

@main.route('/result')
def result():
    """Route to display sentiment analysis results."""
    if not session.get('user'):  # Ensure user is authenticated
        flash("You must be logged in to access this page.")
        return redirect(url_for('login'))

    sentiment = request.args.get('sentiment', 'Unknown')  # Retrieve sentiment from query parameters
    return render_template('result.html', sentiment=sentiment)

# Helper function to predict sentiment
def predict_sentiment(text):
    """
    Predict sentiment based on input text using the trained model.
    Modify this function to match your feature extraction and preprocessing pipeline.
    """
    # Placeholder: Preprocess text as required by your trained model
    features = extract_features(text)  # Define this function to match your model requirements
    sentiment = model.predict([features])[0]  # Predict using the model
    return sentiment.capitalize()  # Ensure the sentiment is displayed nicely (e.g., "Positive")

def extract_features(text):
    """
    Preprocess the text and extract features for prediction.
    Implement the same preprocessing pipeline used during training.
    """
    # Placeholder: Replace with your actual preprocessing and feature extraction
    return text.lower()


