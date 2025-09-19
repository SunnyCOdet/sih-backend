import { Vote, VoteVerificationResult } from '../types';
import { KeyManager } from '../crypto/keyManager';
import { ZeroKnowledgeProofSystem } from '../crypto/zeroKnowledgeProof';
import { Blockchain } from '../blockchain/blockchain';

export class TamperDetectionService {
  private blockchain: Blockchain;
  private suspiciousActivities: Array<{
    timestamp: Date;
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
  }> = [];

  constructor(blockchain: Blockchain) {
    this.blockchain = blockchain;
  }

  /**
   * Detect tampering attempts in vote submissions
   */
  detectTampering(vote: Vote, publicKey: string): VoteVerificationResult {
    try {
      // Check 1: Verify signature authenticity
      const signatureValid = KeyManager.verifySignature(
        vote.voteHash,
        vote.signature,
        publicKey
      );

      if (!signatureValid) {
        this.recordSuspiciousActivity(
          'invalid_signature',
          `Invalid signature detected for vote ${vote.id}`,
          'high'
        );
        return {
          isValid: false,
          reason: 'Tampering detected: Invalid signature'
        };
      }

      // Check 2: Verify zero-knowledge proof integrity
      const zkProofValid = ZeroKnowledgeProofSystem.verifyVoteProof(
        {
          commitment: vote.zeroKnowledgeProof,
          proof: vote.zeroKnowledgeProof,
          publicInputs: [vote.candidateId, vote.voterId]
        },
        vote.candidateId,
        vote.voterId
      );

      if (!zkProofValid) {
        this.recordSuspiciousActivity(
          'invalid_zk_proof',
          `Invalid zero-knowledge proof detected for vote ${vote.id}`,
          'high'
        );
        return {
          isValid: false,
          reason: 'Tampering detected: Invalid zero-knowledge proof'
        };
      }

      // Check 3: Detect duplicate voting attempts
      const existingVote = this.blockchain.findVoteByVoterId(vote.voterId);
      if (existingVote) {
        this.recordSuspiciousActivity(
          'duplicate_vote_attempt',
          `Duplicate vote attempt detected for voter ${vote.voterId}`,
          'high'
        );
        return {
          isValid: false,
          reason: 'Tampering detected: Duplicate vote attempt'
        };
      }

      // Check 4: Verify vote hash consistency
      const expectedHash = KeyManager.createVoteHash(
        vote.candidateId,
        vote.voterId,
        vote.timestamp.getTime()
      );

      if (vote.voteHash !== expectedHash) {
        this.recordSuspiciousActivity(
          'hash_tampering',
          `Vote hash tampering detected for vote ${vote.id}`,
          'high'
        );
        return {
          isValid: false,
          reason: 'Tampering detected: Vote hash has been modified'
        };
      }

      // Check 5: Detect unusual voting patterns
      this.detectUnusualPatterns(vote);

      return { isValid: true };
    } catch (error) {
      this.recordSuspiciousActivity(
        'verification_error',
        `Vote verification error for vote ${vote.id}: ${error}`,
        'medium'
      );
      return {
        isValid: false,
        reason: 'Tampering detection failed'
      };
    }
  }

  /**
   * Detect unusual voting patterns
   */
  private detectUnusualPatterns(vote: Vote): void {
    const allVotes = this.blockchain.getAllVotes();
    
    // Check for rapid successive votes (potential bot activity)
    const recentVotes = allVotes.filter(v => 
      Math.abs(v.timestamp.getTime() - vote.timestamp.getTime()) < 60000 // 1 minute
    );

    if (recentVotes.length > 5) {
      this.recordSuspiciousActivity(
        'rapid_voting',
        `Rapid voting pattern detected around ${vote.timestamp}`,
        'medium'
      );
    }

    // Check for votes with identical timestamps (potential batch tampering)
    const identicalTimestampVotes = allVotes.filter(v => 
      v.timestamp.getTime() === vote.timestamp.getTime()
    );

    if (identicalTimestampVotes.length > 3) {
      this.recordSuspiciousActivity(
        'batch_tampering',
        `Multiple votes with identical timestamp detected`,
        'high'
      );
    }
  }

  /**
   * Verify blockchain integrity for tampering
   */
  verifyBlockchainIntegrity(): {
    isIntact: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    
    // Verify chain integrity
    const isChainIntact = this.blockchain.verifyChain();
    if (!isChainIntact) {
      issues.push('Blockchain chain integrity compromised');
    }

    // Check for hash collisions
    const allVotes = this.blockchain.getAllVotes();
    const voteHashes = allVotes.map(v => v.voteHash);
    const uniqueHashes = new Set(voteHashes);
    
    if (voteHashes.length !== uniqueHashes.size) {
      issues.push('Hash collision detected in votes');
    }

    // Check for timestamp anomalies
    const now = Date.now();
    const futureVotes = allVotes.filter(v => v.timestamp.getTime() > now);
    if (futureVotes.length > 0) {
      issues.push('Future timestamp votes detected');
    }

    return {
      isIntact: issues.length === 0,
      issues
    };
  }

  /**
   * Record suspicious activity
   */
  private recordSuspiciousActivity(
    type: string,
    description: string,
    severity: 'low' | 'medium' | 'high'
  ): void {
    this.suspiciousActivities.push({
      timestamp: new Date(),
      type,
      description,
      severity
    });

    // Log high-severity activities
    if (severity === 'high') {
      console.warn(`[TAMPER DETECTION] ${type}: ${description}`);
    }
  }

  /**
   * Get suspicious activities
   */
  getSuspiciousActivities(): Array<{
    timestamp: Date;
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
  }> {
    return [...this.suspiciousActivities];
  }

  /**
   * Get tamper detection statistics
   */
  getTamperStats(): {
    totalActivities: number;
    bySeverity: Record<string, number>;
    recentActivities: number;
  } {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    
    const recentActivities = this.suspiciousActivities.filter(
      activity => activity.timestamp.getTime() > oneHourAgo
    ).length;

    const bySeverity = this.suspiciousActivities.reduce((acc, activity) => {
      acc[activity.severity] = (acc[activity.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalActivities: this.suspiciousActivities.length,
      bySeverity,
      recentActivities
    };
  }

  /**
   * Clear old suspicious activities (for memory management)
   */
  clearOldActivities(olderThanHours: number = 24): void {
    const cutoffTime = Date.now() - (olderThanHours * 60 * 60 * 1000);
    this.suspiciousActivities = this.suspiciousActivities.filter(
      activity => activity.timestamp.getTime() > cutoffTime
    );
  }
}
