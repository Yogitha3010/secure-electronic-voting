from flask_wtf import FlaskForm
from wtforms import DateTimeLocalField, PasswordField, RadioField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp, ValidationError


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30),
            Regexp(r"^[A-Za-z0-9_]+$", message="Use letters, numbers, and underscores only."),
        ],
    )
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128)])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create voter account")


class LoginForm(FlaskForm):
    identifier = StringField("Username or email", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


class ElectionForm(FlaskForm):
    title = StringField("Election title", validators=[DataRequired(), Length(min=3, max=120)])
    description = TextAreaField("Description", validators=[Optional(), Length(max=500)])
    start_at = DateTimeLocalField("Start date and time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    end_at = DateTimeLocalField("End date and time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    submit = SubmitField("Create election")

    def validate_end_at(self, field):
        if self.start_at.data and field.data and field.data <= self.start_at.data:
            raise ValidationError("End date and time must be after the start date and time.")


class CandidateForm(FlaskForm):
    name = StringField("Candidate name", validators=[DataRequired(), Length(min=2, max=120)])
    affiliation = StringField("Party / affiliation", validators=[Optional(), Length(max=120)])
    submit = SubmitField("Add candidate")


class EmptyForm(FlaskForm):
    pass


class VoteForm(FlaskForm):
    candidate_id = RadioField("Choose one candidate", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Encrypt and cast vote")
