import * as crypto from 'crypto';
import { Block, Vote, VoteVerificationResult } from '../types';
import { KeyManager } from '../crypto/keyManager';
import { ZeroKnowledgeProofSystem } from '../crypto/zeroKnowledgeProof';

export class Blockchain {
  private chain: Block[] = [];
  private pendingVotes: Vote[] = [];
  private readonly difficulty = 4; // Mining difficulty
  private readonly maxVotesPerBlock = 10;

  constructor() {
    // Create genesis block
    this.createGenesisBlock();
  }

  /**
   * Create the genesis block
   */
  private createGenesisBlock(): void {
    const genesisBlock: Block = {
      index: 0,
      timestamp: new Date(),
      previousHash: '0',
      hash: '0',
      votes: [],
      merkleRoot: '0'
    };

    genesisBlock.hash = this.calculateBlockHash(genesisBlock);
    this.chain.push(genesisBlock);
  }

  /**
   * Add a new vote to the blockchain
   */
  addVote(vote: Vote): VoteVerificationResult {
    try {
      // Verify the vote
      const verification = this.verifyVote(vote);
      if (!verification.isValid) {
        return verification;
      }

      // Add to pending votes
      this.pendingVotes.push(vote);

      // Mine block if we have enough votes
      if (this.pendingVotes.length >= this.maxVotesPerBlock) {
        this.mineBlock();
      }

      return {
        isValid: true,
        blockIndex: this.chain.length
      };
    } catch (error) {
      return {
        isValid: false,
        reason: 'Failed to add vote to blockchain'
      };
    }
  }

  /**
   * Verify a vote before adding to blockchain
   */
  verifyVote(vote: Vote): VoteVerificationResult {
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

      // Check for duplicate votes (same voter)
      const existingVote = this.findVoteByVoterId(vote.voterId);
      if (existingVote) {
        return {
          isValid: false,
          reason: 'Voter has already voted'
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
   * Mine a new block with pending votes
   */
  private mineBlock(): void {
    const previousBlock = this.chain[this.chain.length - 1];
    const merkleRoot = this.calculateMerkleRoot(this.pendingVotes);

    const newBlock: Block = {
      index: this.chain.length,
      timestamp: new Date(),
      previousHash: previousBlock.hash,
      hash: '',
      votes: [...this.pendingVotes],
      merkleRoot
    };

    // Mine the block (simplified proof of work)
    newBlock.hash = this.mineBlockHash(newBlock);
    
    // Add block to chain
    this.chain.push(newBlock);
    
    // Clear pending votes
    this.pendingVotes = [];
  }

  /**
   * Mine block hash with proof of work
   */
  private mineBlockHash(block: Block): string {
    let nonce = 0;
    let hash: string;

    do {
      const blockData = this.getBlockData(block, nonce);
      hash = crypto.createHash('sha256').update(blockData).digest('hex');
      nonce++;
    } while (!hash.startsWith('0'.repeat(this.difficulty)));

    return hash;
  }

  /**
   * Get block data for hashing
   */
  private getBlockData(block: Block, nonce: number): string {
    return `${block.index}${block.timestamp.getTime()}${block.previousHash}${block.merkleRoot}${nonce}`;
  }

  /**
   * Calculate block hash
   */
  private calculateBlockHash(block: Block): string {
    const blockData = this.getBlockData(block, 0);
    return crypto.createHash('sha256').update(blockData).digest('hex');
  }

  /**
   * Calculate Merkle root for votes
   */
  private calculateMerkleRoot(votes: Vote[]): string {
    if (votes.length === 0) return '0';
    
    const hashes = votes.map(vote => 
      crypto.createHash('sha256').update(vote.voteHash).digest('hex')
    );

    return this.buildMerkleTree(hashes);
  }

  /**
   * Build Merkle tree
   */
  private buildMerkleTree(hashes: string[]): string {
    if (hashes.length === 1) return hashes[0];

    const nextLevel: string[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i];
      const right = hashes[i + 1] || left;
      const combined = crypto.createHash('sha256')
        .update(left + right)
        .digest('hex');
      nextLevel.push(combined);
    }

    return this.buildMerkleTree(nextLevel);
  }

  /**
   * Find vote by voter ID
   */
  findVoteByVoterId(voterId: string): Vote | null {
    for (const block of this.chain) {
      for (const vote of block.votes) {
        if (vote.voterId === voterId) {
          return vote;
        }
      }
    }
    return null;
  }

  /**
   * Get all votes
   */
  getAllVotes(): Vote[] {
    const votes: Vote[] = [];
    for (const block of this.chain) {
      votes.push(...block.votes);
    }
    return votes;
  }

  /**
   * Get blockchain info
   */
  getBlockchainInfo(): { 
    chainLength: number; 
    totalVotes: number; 
    pendingVotes: number;
    lastBlockHash: string;
  } {
    const totalVotes = this.getAllVotes().length;
    
    return {
      chainLength: this.chain.length,
      totalVotes,
      pendingVotes: this.pendingVotes.length,
      lastBlockHash: this.chain[this.chain.length - 1].hash
    };
  }

  /**
   * Force mine pending votes (for demo purposes)
   */
  forceMineBlock(): void {
    if (this.pendingVotes.length > 0) {
      this.mineBlock();
    }
  }

  /**
   * Verify blockchain integrity
   */
  verifyChain(): boolean {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      // Check if current block's previous hash matches previous block's hash
      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }

      // Check if current block's hash is valid
      const calculatedHash = this.calculateBlockHash(currentBlock);
      if (currentBlock.hash !== calculatedHash) {
        return false;
      }
    }

    return true;
  }
}
