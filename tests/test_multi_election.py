import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

_temp_dir = tempfile.TemporaryDirectory()
os.environ["SECRET_KEY"] = "test-secret-key-for-multi-election-tests"
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_temp_dir.name, 'test.db').as_posix()}"
os.environ["VOTING_AES_KEY_PATH"] = str(Path(_temp_dir.name) / "voting_aes.key")

from app import app, db  # noqa: E402
from crypto_service import encrypt_vote, generate_vote_key  # noqa: E402
from models import Candidate, Election, User, Vote, VoterParticipation  # noqa: E402
from results_service import calculate_election_results  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402


class MultipleElectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with app.app_context():
            db.drop_all()
            db.create_all()
            generate_vote_key(app.config["VOTING_AES_KEY_PATH"])

    def setUp(self):
        with app.app_context():
            db.session.query(VoterParticipation).delete()
            db.session.query(Vote).delete()
            db.session.query(Candidate).delete()
            db.session.query(Election).delete()
            db.session.query(User).delete()
            db.session.commit()

    def create_election(self, title, status):
        election = Election(
            title=title,
            status=status,
            start_at=datetime.now() - timedelta(minutes=5),
            end_at=datetime.now() + timedelta(hours=1),
        )
        db.session.add(election)
        db.session.flush()
        return election

    def cast_vote(self, election, voter, candidate):
        encrypted = encrypt_vote(
            {"candidate_id": candidate.id},
            app.config["VOTING_AES_KEY_PATH"],
            f"election:{election.id}".encode("utf-8"),
        )
        db.session.add(VoterParticipation(election_id=election.id, voter_id=voter.id))
        db.session.add(Vote(election_id=election.id, **encrypted))
        db.session.commit()

    def test_multiple_elections_keep_candidates_votes_and_results_isolated(self):
        with app.app_context():
            first = self.create_election("College President", "ACTIVE")
            second = self.create_election("Department Representative", "ACTIVE")
            first_candidate = Candidate(election_id=first.id, name="Alice")
            second_candidate = Candidate(election_id=second.id, name="Bob")
            voter = User(username="voter_one", email="one@example.com", role="voter", password_hash="hash")
            db.session.add_all([first_candidate, second_candidate, voter])
            db.session.commit()

            self.cast_vote(first, voter, first_candidate)
            self.cast_vote(second, voter, second_candidate)

            first_results = calculate_election_results(first, app.config["VOTING_AES_KEY_PATH"], None, None, app.logger)
            second_results = calculate_election_results(second, app.config["VOTING_AES_KEY_PATH"], None, None, app.logger)
            self.assertEqual([row["candidate"].name for row in first_results["rows"]], ["Alice"])
            self.assertEqual([row["votes"] for row in first_results["rows"]], [1])
            self.assertEqual([row["candidate"].name for row in second_results["rows"]], ["Bob"])
            self.assertEqual([row["votes"] for row in second_results["rows"]], [1])

    def test_one_vote_per_election_allows_a_vote_in_another_election(self):
        with app.app_context():
            first = self.create_election("Election One", "ACTIVE")
            second = self.create_election("Election Two", "ACTIVE")
            first_candidate = Candidate(election_id=first.id, name="Alice")
            second_candidate = Candidate(election_id=second.id, name="Bob")
            voter = User(username="voter_two", email="two@example.com", role="voter", password_hash="hash")
            db.session.add_all([first_candidate, second_candidate, voter])
            db.session.commit()

            self.cast_vote(first, voter, first_candidate)
            self.cast_vote(second, voter, second_candidate)
            self.assertEqual(VoterParticipation.query.filter_by(voter_id=voter.id).count(), 2)

            with self.assertRaises(IntegrityError):
                db.session.add(VoterParticipation(election_id=first.id, voter_id=voter.id))
                db.session.commit()
            db.session.rollback()

    def test_upcoming_and_closed_elections_are_not_open_for_voting(self):
        with app.app_context():
            upcoming = Election(title="Upcoming", status="UPCOMING")
            closed = Election(title="Closed", status="CLOSED")
            self.assertFalse(upcoming.is_open_for_voting)
            self.assertFalse(closed.is_open_for_voting)

    def test_percentages_are_calculated_per_election(self):
        with app.app_context():
            election = self.create_election("Percentages", "ACTIVE")
            alice = Candidate(election_id=election.id, name="Alice")
            bob = Candidate(election_id=election.id, name="Bob")
            voters = [
                User(username=f"voter_{index}", email=f"{index}@example.com", role="voter", password_hash="hash")
                for index in range(3)
            ]
            db.session.add_all([alice, bob, *voters])
            db.session.commit()
            self.cast_vote(election, voters[0], alice)
            self.cast_vote(election, voters[1], alice)
            self.cast_vote(election, voters[2], bob)
            results = calculate_election_results(election, app.config["VOTING_AES_KEY_PATH"], None, None, app.logger)
            self.assertEqual(results["total_votes"], 3)
            self.assertEqual([row["percentage"] for row in results["rows"]], [66.7, 33.3])
