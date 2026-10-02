from datetime import datetime, timezone

from flask_login import UserMixin

from app import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="voter")

    __table_args__ = (
        db.CheckConstraint("role IN ('admin', 'voter')", name="valid_user_role"),
    )

    def set_password(self, password):
        from werkzeug.security import generate_password_hash

        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash

        return check_password_hash(self.password_hash, password)


class Election(db.Model):
    __tablename__ = "elections"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.String(500), nullable=False, default="")
    # is_active remains only for compatibility with databases from the earlier stage.
    is_active = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(10), nullable=False, default="UPCOMING", index=True)
    start_at = db.Column(db.DateTime, nullable=True)
    end_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    candidates = db.relationship(
        "Candidate", back_populates="election", cascade="all, delete-orphan", lazy="select"
    )
    votes = db.relationship("Vote", back_populates="election", lazy="select")

    @property
    def effective_status(self):
        """Return the status after enforcing the configured end time."""
        if self.status == "CLOSED" or (self.end_at and self.end_at <= datetime.now()):
            return "CLOSED"
        if self.status == "ACTIVE":
            return "ACTIVE"
        return "UPCOMING"

    @property
    def is_open_for_voting(self):
        return self.effective_status == "ACTIVE"


class Candidate(db.Model):
    __tablename__ = "candidates"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    affiliation = db.Column(db.String(120), nullable=False, default="Independent")
    election = db.relationship("Election", back_populates="candidates")

    __table_args__ = (
        db.UniqueConstraint("election_id", "name", name="unique_candidate_per_election"),
    )


class VoterParticipation(db.Model):
    """Records eligibility use without storing a selected candidate."""

    __tablename__ = "voter_participations"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    voted_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        db.UniqueConstraint("election_id", "voter_id", name="one_vote_per_voter_per_election"),
    )


class Vote(db.Model):
    """An AES-GCM encrypted ballot with no voter identifier or plaintext choice."""

    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False, index=True)
    encrypted_vote = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(24), nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    election = db.relationship("Election", back_populates="votes")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
