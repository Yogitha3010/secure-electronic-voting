import os
import re
from datetime import datetime
from pathlib import Path

import click
from email_validator import EmailNotValidError, validate_email
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, url_for
from flask.cli import with_appcontext
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from crypto_service import (
    VoteDecryptionError,
    VoteEncryptionError,
    decrypt_vote,
    encrypt_vote,
    generate_vote_key,
)
from forms import CandidateForm, ElectionForm, EmptyForm, LoginForm, RegistrationForm, VoteForm


BASE_DIR = Path(__file__).resolve().parent
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
csrf = CSRFProtect()


def admin_required(view):
    """Restrict a view to authenticated administrator accounts."""
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY must be set in the environment before starting the application.")

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            f"sqlite:///{(BASE_DIR / 'instance' / 'secure_voting.db').as_posix()}",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        VOTING_AES_KEY_PATH=os.environ.get(
            "VOTING_AES_KEY_PATH", str(BASE_DIR / "instance" / "keys" / "voting_aes.key")
        ),
        VOTING_RSA_PRIVATE_KEY_PATH=os.environ.get(
            "VOTING_RSA_PRIVATE_KEY_PATH", str(BASE_DIR / "instance" / "keys" / "vote_rsa_private.pem")
        ),
        VOTING_RSA_PUBLIC_KEY_PATH=os.environ.get(
            "VOTING_RSA_PUBLIC_KEY_PATH", str(BASE_DIR / "instance" / "keys" / "vote_rsa_public.pem")
        ),
        VOTING_RSA_PASSPHRASE=os.environ.get("VOTING_RSA_PASSPHRASE"),
    )

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()
        apply_schema_updates()

    register_routes(app)
    register_commands(app)
    return app


def apply_schema_updates():
    """Add nullable scheduling/status columns to an existing SQLite database safely."""
    if db.engine.url.get_backend_name() != "sqlite" or "elections" not in inspect(db.engine).get_table_names():
        return
    columns = {column["name"] for column in inspect(db.engine).get_columns("elections")}
    with db.engine.begin() as connection:
        if "status" not in columns:
            connection.execute(text("ALTER TABLE elections ADD COLUMN status VARCHAR(10)"))
            connection.execute(
                text("UPDATE elections SET status = CASE WHEN is_active = 1 THEN 'ACTIVE' ELSE 'UPCOMING' END")
            )
        if "start_at" not in columns:
            connection.execute(text("ALTER TABLE elections ADD COLUMN start_at DATETIME"))
        if "end_at" not in columns:
            connection.execute(text("ALTER TABLE elections ADD COLUMN end_at DATETIME"))
    vote_columns = {column["name"] for column in inspect(db.engine).get_columns("votes")}
    if "encrypted_aes_key" not in vote_columns:
        with db.engine.begin() as connection:
            connection.execute(text("ALTER TABLE votes ADD COLUMN encrypted_aes_key TEXT"))


def synchronize_election_statuses():
    """Close expired elections before they are displayed, voted in, or tallied."""
    from datetime import datetime

    Election.query.filter(
        Election.status == "ACTIVE", Election.end_at.isnot(None), Election.end_at <= datetime.now()
    ).update({"status": "CLOSED", "is_active": False}, synchronize_session=False)
    db.session.commit()


def register_routes(app):
    @app.get("/")
    def home():
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("home"))

        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data.strip().lower()
            email = form.email.data.strip().lower()
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("That username or email address is already registered.", "danger")
                return render_template("register.html", form=form)

            user = User(username=username, email=email, role="voter")
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. You can now sign in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("home"))

        form = LoginForm()
        if form.validate_on_submit():
            identifier = form.identifier.data.strip().lower()
            user = User.query.filter(
                (User.username == identifier) | (User.email == identifier)
            ).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash("Signed in successfully.", "success")
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("home"))
            flash("Invalid username/email or password.", "danger")
        return render_template("login.html", form=form)

    @app.post("/logout")
    def logout():
        logout_user()
        flash("You have been signed out.", "info")
        return redirect(url_for("home"))

    @app.get("/vote")
    @login_required
    def voter_dashboard():
        if current_user.role != "voter":
            return redirect(url_for("admin_dashboard"))
        synchronize_election_statuses()
        elections = Election.query.filter_by(status="ACTIVE").order_by(Election.start_at).all()
        participated_election_ids = {
            participation.election_id
            for participation in VoterParticipation.query.filter_by(voter_id=current_user.id).all()
        }
        return render_template(
            "voter_dashboard.html", elections=elections, participated_election_ids=participated_election_ids
        )

    @app.route("/elections/<int:election_id>/vote", methods=["GET", "POST"])
    @login_required
    def cast_vote(election_id):
        if current_user.role != "voter":
            abort(403)
        synchronize_election_statuses()
        election = db.get_or_404(Election, election_id)
        if not election.is_open_for_voting:
            flash("This election is not currently open for voting.", "warning")
            return redirect(url_for("voter_dashboard"))

        participation = VoterParticipation.query.filter_by(
            election_id=election.id, voter_id=current_user.id
        ).first()
        if participation:
            flash("Your vote for this election has already been recorded.", "info")
            return redirect(url_for("voter_dashboard"))

        candidates = Candidate.query.filter_by(election_id=election.id).order_by(Candidate.name).all()
        if not candidates:
            flash("This election has no candidates and cannot accept votes.", "warning")
            return redirect(url_for("voter_dashboard"))
        form = VoteForm()
        form.candidate_id.choices = [
            (candidate.id, f"{candidate.name} ({candidate.affiliation})") for candidate in candidates
        ]
        if form.validate_on_submit():
            candidate = db.session.get(Candidate, form.candidate_id.data)
            if not candidate or candidate.election_id != election.id:
                abort(400)
            try:
                encrypted = encrypt_vote(
                    {"candidate_id": candidate.id},
                    app.config["VOTING_AES_KEY_PATH"],
                    associated_data=f"election:{election.id}".encode("utf-8"),
                    rsa_public_key_path=app.config["VOTING_RSA_PUBLIC_KEY_PATH"],
                )
            except VoteEncryptionError:
                app.logger.exception("Voting key configuration error")
                flash("Voting is temporarily unavailable. Please contact the administrator.", "danger")
                return redirect(url_for("voter_dashboard"))

            db.session.add(VoterParticipation(election_id=election.id, voter_id=current_user.id))
            db.session.add(Vote(election_id=election.id, **encrypted))
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("Your vote for this election has already been recorded.", "info")
                return redirect(url_for("voter_dashboard"))
            flash("Your encrypted vote has been recorded successfully.", "success")
            return redirect(url_for("voter_dashboard"))
        return render_template("cast_vote.html", election=election, form=form)

    @app.route("/admin", methods=["GET", "POST"])
    @admin_required
    def admin_dashboard():
        synchronize_election_statuses()
        form = ElectionForm()
        if form.validate_on_submit():
            title = form.title.data.strip()
            if Election.query.filter_by(title=title).first():
                flash("An election with that title already exists.", "danger")
            else:
                election = Election(
                    title=title,
                    description=(form.description.data or "").strip(),
                    start_at=form.start_at.data,
                    end_at=form.end_at.data,
                    status="UPCOMING",
                )
                db.session.add(election)
                db.session.commit()
                flash("Election created. Add candidates before starting it.", "success")
                return redirect(url_for("admin_dashboard"))

        elections = Election.query.order_by(Election.start_at.desc()).all()
        vote_counts = {
            election.id: Vote.query.filter_by(election_id=election.id).count() for election in elections
        }
        return render_template(
            "admin_dashboard.html",
            form=form,
            elections=elections,
            vote_counts=vote_counts,
            control_form=EmptyForm(),
        )

    @app.route("/admin/elections/<int:election_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_election(election_id):
        election = db.get_or_404(Election, election_id)
        if election.effective_status == "CLOSED":
            flash("Closed elections cannot be edited.", "warning")
            return redirect(url_for("admin_dashboard"))
        form = ElectionForm(obj=election)
        if form.validate_on_submit():
            duplicate = Election.query.filter(Election.title == form.title.data.strip(), Election.id != election.id).first()
            if duplicate:
                flash("An election with that title already exists.", "danger")
            else:
                election.title = form.title.data.strip()
                election.description = (form.description.data or "").strip()
                election.start_at = form.start_at.data
                election.end_at = form.end_at.data
                db.session.commit()
                flash("Election details updated.", "success")
                return redirect(url_for("admin_dashboard"))
        return render_template("edit_election.html", election=election, form=form)

    @app.get("/admin/elections/<int:election_id>")
    @admin_required
    def election_details(election_id):
        synchronize_election_statuses()
        election = db.get_or_404(Election, election_id)
        vote_count = Vote.query.filter_by(election_id=election.id).count()
        return render_template("election_details.html", election=election, vote_count=vote_count)

    @app.get("/admin/elections/<int:election_id>/results")
    @admin_required
    def election_results(election_id):
        synchronize_election_statuses()
        election = db.get_or_404(Election, election_id)
        from results_service import calculate_election_results

        try:
            results = calculate_election_results(
                election,
                app.config["VOTING_AES_KEY_PATH"],
                app.config["VOTING_RSA_PRIVATE_KEY_PATH"],
                app.config["VOTING_RSA_PASSPHRASE"],
                app.logger,
            )
        except VoteEncryptionError:
            app.logger.exception("RSA private key configuration error during result calculation")
            flash("Results are temporarily unavailable. Please contact the administrator.", "danger")
            return redirect(url_for("admin_dashboard"))
        registered_voters = User.query.filter_by(role="voter").count()
        turnout = round((results["total_votes"] / registered_voters * 100) if registered_voters else 0, 1)
        return render_template(
            "election_results.html",
            election=election,
            results=results,
            registered_voters=registered_voters,
            turnout=turnout,
        )

    @app.route("/admin/elections/<int:election_id>/candidates", methods=["GET", "POST"])
    @admin_required
    def manage_candidates(election_id):
        election = db.get_or_404(Election, election_id)
        form = CandidateForm()
        if form.validate_on_submit():
            if election.effective_status != "UPCOMING":
                flash("Stop the election before changing its candidates.", "danger")
            else:
                name = form.name.data.strip()
                if Candidate.query.filter_by(election_id=election.id, name=name).first():
                    flash("That candidate has already been added to this election.", "danger")
                else:
                    candidate = Candidate(
                        election=election,
                        name=name,
                        affiliation=(form.affiliation.data or "Independent").strip() or "Independent",
                    )
                    db.session.add(candidate)
                    db.session.commit()
                    flash("Candidate added.", "success")
                    return redirect(url_for("manage_candidates", election_id=election.id))
        return render_template("manage_candidates.html", election=election, form=form)

    @app.post("/admin/elections/<int:election_id>/toggle")
    @admin_required
    def toggle_election(election_id):
        form = EmptyForm()
        if not form.validate_on_submit():
            abort(400)
        election = db.get_or_404(Election, election_id)
        if election.effective_status == "CLOSED":
            flash("This election is already closed and cannot be restarted.", "warning")
        elif election.effective_status == "ACTIVE":
            election.status = "CLOSED"
            election.is_active = False
            flash("Election closed. No new votes can be cast.", "info")
        elif not election.candidates:
            flash("Add at least one candidate before starting an election.", "danger")
        elif election.start_at and election.start_at > datetime.now():
            flash("This election is upcoming and cannot start before its scheduled start time.", "warning")
        else:
            Election.query.filter_by(status="ACTIVE").update({"status": "CLOSED", "is_active": False})
            election.status = "ACTIVE"
            election.is_active = True
            flash("Election started.", "success")
        db.session.commit()
        return redirect(url_for("admin_dashboard"))


def register_commands(app):
    @app.cli.command("init-db")
    @with_appcontext
    def init_db_command():
        """Create the SQLite tables without deleting existing data."""
        db.create_all()
        apply_schema_updates()
        click.echo("Database tables are ready.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Admin username")
    @click.option("--email", prompt=True, help="Admin email address")
    @click.password_option(confirmation_prompt=True)
    @with_appcontext
    def create_admin_command(username, email, password):
        """Create an administrator account interactively."""
        username = username.strip().lower()
        email = email.strip().lower()
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            raise click.ClickException("Username must be 3-30 letters, numbers, or underscores.")
        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError as error:
            raise click.ClickException(f"Invalid email address: {error}") from error
        if User.query.filter((User.username == username) | (User.email == email)).first():
            raise click.ClickException("That username or email address is already registered.")
        if len(password) < 12:
            raise click.ClickException("Admin password must contain at least 12 characters.")

        admin = User(username=username, email=email, role="admin")
        admin.password_hash = generate_password_hash(password)
        db.session.add(admin)
        db.session.commit()
        click.echo("Administrator account created.")

    @app.cli.command("generate-voting-aes-key")
    @with_appcontext
    def generate_voting_aes_key_command():
        """Generate the local persistent AES-256 key used for ballot encryption."""
        try:
            generate_vote_key(app.config["VOTING_AES_KEY_PATH"])
        except FileExistsError as error:
            raise click.ClickException(str(error)) from error
        click.echo("AES voting key created in the protected instance directory.")

    @app.cli.command("generate-voting-rsa-keys")
    @click.password_option(confirmation_prompt=True)
    @with_appcontext
    def generate_voting_rsa_keys_command(password):
        """Generate the RSA-OAEP key pair that protects the AES voting key."""
        if len(password) < 16:
            raise click.ClickException("RSA key passphrase must contain at least 16 characters.")
        from crypto_service import generate_rsa_key_pair

        try:
            generate_rsa_key_pair(
                app.config["VOTING_RSA_PRIVATE_KEY_PATH"],
                app.config["VOTING_RSA_PUBLIC_KEY_PATH"],
                password,
            )
        except FileExistsError as error:
            raise click.ClickException(str(error)) from error
        click.echo("RSA key pair created. Set VOTING_RSA_PASSPHRASE before running results.")

    @app.cli.command("count-votes")
    @click.option("--election-id", type=int, required=True, help="Election ID to tally")
    @with_appcontext
    def count_votes_command(election_id):
        """Decrypt and print aggregate totals only for a stopped election."""
        election = db.session.get(Election, election_id)
        if not election:
            raise click.ClickException("Election was not found.")
        synchronize_election_statuses()
        if election.effective_status == "ACTIVE":
            raise click.ClickException("Stop the election before counting votes.")

        from results_service import calculate_election_results

        try:
            results = calculate_election_results(
                election,
                app.config["VOTING_AES_KEY_PATH"],
                app.config["VOTING_RSA_PRIVATE_KEY_PATH"],
                app.config["VOTING_RSA_PASSPHRASE"],
                app.logger,
            )
        except VoteEncryptionError as error:
            raise click.ClickException("RSA private key configuration is unavailable.") from error

        click.echo(f"Aggregate results for: {election.title}")
        for row in results["rows"]:
            click.echo(f"{row['candidate'].name}: {row['votes']}")
        click.echo(f"Invalid or unauthenticated ballots excluded: {results['invalid_ballots']}")


from models import (  # noqa: E402  (models need the db instance defined above)
    Candidate,
    Election,
    User,
    VoterParticipation,
    Vote,
)

app = create_app()
