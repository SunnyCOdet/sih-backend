import { Vote, VoteSubmission, VoteVerificationResult } from '../types';
import { KeyManager } from '../crypto/keyManager';
import { ZeroKnowledgeProofSystem } from '../crypto/zeroKnowledgeProof';
import { VoterRegistrationService } from './voterRegistration';
import { Blockchain } from '../blockchain/blockchain';
import { v4 as uuidv4 } from 'uuid';

export class VoteService {
  private voterRegistration: VoterRegistrationService;
  private blockchain: Blockchain;

  constructor(voterRegistration: VoterRegistrationService, blockchain: Blockchain) {
    this.voterRegistration = voterRegistration;
    this.blockchain = blockchain;
  }

  /**
   * Submit a vote to the system
   */
  async submitVote(voteSubmission: VoteSubmission): Promise<VoteVerificationResult> {
    try {
      // Find voter by public key
      const voter = this.voterRegistration.getVoterByPublicKey(voteSubmission.publicKey);
      if (!voter) {
        return {
          isValid: false,
          reason: 'Voter not found or not registered'
        };
      }

      // Check if voter is eligible to vote
      if (!this.voterRegistration.isVoterEligible(voter.id)) {
        return {
          isValid: false,
          reason: 'Voter has already voted or is not eligible'
        };
      }

      // Verify signature
      const isSignatureValid = KeyManager.verifySignature(
        voteSubmission.voteHash,
        voteSubmission.signature,
        voteSubmission.publicKey
      );

      if (!isSignatureValid) {
        return {
          isValid: false,
          reason: 'Invalid signature'
        };
      }

      // Create vote object
      const vote: Vote = {
        id: uuidv4(),
        voterId: voter.id,
        candidateId: voteSubmission.candidateId,
        voteHash: voteSubmission.voteHash,
        signature: voteSubmission.signature,
        zeroKnowledgeProof: voteSubmission.zeroKnowledgeProof,
        timestamp: new Date(),
        publicKey: voteSubmission.publicKey
      };

      // Add vote to blockchain
      const result = this.blockchain.addVote(vote);
      
      if (result.isValid) {
        // Mark voter as having voted
        this.voterRegistration.markVoterAsVoted(voter.id);
      }

      return result;
    } catch (error) {
      return {
        isValid: false,
        reason: 'Vote submission failed'
      };
    }
  }

  /**
   * Create a vote with zero-knowledge proof
   */
  createVoteWithProof(
    candidateId: string, 
    voterId: string, 
    privateKey: string
  ): { voteHash: string; zeroKnowledgeProof: string; signature: string } {
    // Generate vote hash
    const timestamp = Date.now();
    const voteHash = KeyManager.createVoteHash(candidateId, voterId, timestamp);
    
    // Create zero-knowledge proof
    const secret = crypto.randomBytes(32).toString('hex');
    const zkProof = ZeroKnowledgeProofSystem.createVoteProof(candidateId, voterId, secret);
    
    // Sign the vote hash
    const signature = KeyManager.signMessage(voteHash, privateKey);
    
    return {
      voteHash,
      zeroKnowledgeProof: zkProof.commitment,
      signature
    };
  }

  /**
   * Verify a vote's integrity
   */
  verifyVoteIntegrity(vote: Vote): VoteVerificationResult {
    try {
      // Verify signature
      const isSignatureValid = KeyManager.verifySignature(
        vote.voteHash,
        vote.signature,
        vote.publicKey || ''
      );

      if (!isSignatureValid) {
        return {
          isValid: false,
          reason: 'Invalid signature'
        };
      }

      // Verify zero-knowledge proof (simplified for demo)
      // In a real implementation, this would use proper ZK proof verification
      const isZKProofValid = vote.zeroKnowledgeProof && vote.zeroKnowledgeProof.length > 0;

      if (!isZKProofValid) {
        return {
          isValid: false,
          reason: 'Invalid zero-knowledge proof'
        };
      }

      return { isValid: true };
    } catch (error) {
      return {
        isValid: false,
        reason: 'Vote verification failed'
      };
    }
  }

  /**
   * Get all votes (for transparency)
   */
  getAllVotes(): Vote[] {
    return this.blockchain.getAllVotes();
  }

  /**
   * Get votes by candidate
   */
  getVotesByCandidate(candidateId: string): Vote[] {
    return this.getAllVotes().filter(vote => vote.candidateId === candidateId);
  }

  /**
   * Get vote count by candidate
   */
  getVoteCounts(): Record<string, number> {
    const votes = this.getAllVotes();
    const counts: Record<string, number> = {};
    
    votes.forEach(vote => {
      counts[vote.candidateId] = (counts[vote.candidateId] || 0) + 1;
    });
    
    return counts;
  }

  /**
   * Verify blockchain integrity
   */
  verifyBlockchainIntegrity(): boolean {
    return this.blockchain.verifyChain();
  }

  /**
   * Get voting statistics
   */
  getVotingStats(): {
    totalVotes: number;
    voteCounts: Record<string, number>;
    blockchainInfo: any;
    voterStats: any;
  } {
    return {
      totalVotes: this.getAllVotes().length,
      voteCounts: this.getVoteCounts(),
      blockchainInfo: this.blockchain.getBlockchainInfo(),
      voterStats: this.voterRegistration.getVoterStats()
    };
  }
}

// Import crypto for the createVoteWithProof method
import * as crypto from 'crypto';
