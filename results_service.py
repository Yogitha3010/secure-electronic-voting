from collections import Counter

from crypto_service import VoteDecryptionError, VoteEncryptionError, decrypt_vote
from models import Candidate, Vote


def calculate_election_results(election, key_path, private_key_path, rsa_passphrase, logger):
    """Decrypt ballots for one election and return aggregates only."""
    candidates = Candidate.query.filter_by(election_id=election.id).order_by(Candidate.name).all()
    counts = Counter({candidate.id: 0 for candidate in candidates})
    invalid_ballots = 0

    votes = Vote.query.filter_by(election_id=election.id).all()
    if any(vote.encrypted_aes_key for vote in votes) and not rsa_passphrase:
        raise VoteEncryptionError("RSA private-key passphrase is unavailable.")
    for vote in votes:
        try:
            data = decrypt_vote(
                vote.encrypted_vote,
                vote.nonce,
                key_path,
                associated_data=f"election:{election.id}".encode("utf-8"),
                encrypted_aes_key=vote.encrypted_aes_key,
                rsa_private_key_path=private_key_path,
                rsa_passphrase=rsa_passphrase,
            )
            candidate_id = data.get("candidate_id")
            if candidate_id not in counts:
                raise VoteDecryptionError("Ballot references an invalid candidate.")
            counts[candidate_id] += 1
        except (VoteDecryptionError, VoteEncryptionError):
            invalid_ballots += 1
            logger.warning("Excluded an invalid encrypted ballot during aggregate tally.")

    total_votes = sum(counts.values())
    rows = [
        {
            "candidate": candidate,
            "votes": counts[candidate.id],
            "percentage": round((counts[candidate.id] / total_votes * 100) if total_votes else 0, 1),
        }
        for candidate in candidates
    ]
    return {"rows": rows, "total_votes": total_votes, "invalid_ballots": invalid_ballots}
