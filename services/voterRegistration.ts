import { Voter, VoterRegistration } from '../types';
import { KeyManager } from '../crypto/keyManager';

export class VoterRegistrationService {
  private voters: Map<string, Voter> = new Map();
  private registeredPublicKeys: Set<string> = new Set();

  /**
   * Register a new voter
   */
  registerVoter(registrationData: VoterRegistration): { success: boolean; voter?: Voter; error?: string } {
    try {
      // Check if voter is already registered
      if (this.voters.has(registrationData.voterId)) {
        return { success: false, error: 'Voter already registered' };
      }

      // Check if public key is already in use
      if (this.registeredPublicKeys.has(registrationData.publicKey)) {
        return { success: false, error: 'Public key already in use' };
      }

      // Validate public key format (basic validation)
      if (!this.isValidPublicKey(registrationData.publicKey)) {
        return { success: false, error: 'Invalid public key format' };
      }

      // Create voter record
      const voter: Voter = {
        id: registrationData.voterId,
        publicKey: registrationData.publicKey,
        isRegistered: true,
        hasVoted: false,
        registrationDate: new Date()
      };

      // Store voter and public key
      this.voters.set(voter.id, voter);
      this.registeredPublicKeys.add(voter.publicKey);

      return { success: true, voter };
    } catch (error) {
      return { success: false, error: 'Registration failed' };
    }
  }

  /**
   * Get voter by ID
   */
  getVoter(voterId: string): Voter | null {
    return this.voters.get(voterId) || null;
  }

  /**
   * Get voter by public key
   */
  getVoterByPublicKey(publicKey: string): Voter | null {
    for (const voter of this.voters.values()) {
      if (voter.publicKey === publicKey) {
        return voter;
      }
    }
    return null;
  }

  /**
   * Verify if a voter is registered and eligible to vote
   */
  isVoterEligible(voterId: string): boolean {
    const voter = this.getVoter(voterId);
    return voter ? voter.isRegistered && !voter.hasVoted : false;
  }

  /**
   * Mark a voter as having voted
   */
  markVoterAsVoted(voterId: string): boolean {
    const voter = this.getVoter(voterId);
    if (voter && voter.isRegistered) {
      voter.hasVoted = true;
      return true;
    }
    return false;
  }

  /**
   * Get all registered voters
   */
  getAllVoters(): Voter[] {
    return Array.from(this.voters.values());
  }

  /**
   * Get voter statistics
   */
  getVoterStats(): { total: number; voted: number; remaining: number } {
    const voters = this.getAllVoters();
    const voted = voters.filter(v => v.hasVoted).length;
    
    return {
      total: voters.length,
      voted,
      remaining: voters.length - voted
    };
  }

  /**
   * Validate public key format (simplified validation)
   */
  private isValidPublicKey(publicKey: string): boolean {
    // Basic validation for elliptic curve public keys
    // secp256k1 public keys are typically 130 characters (0x04 + 64 bytes * 2)
    // or 66 characters for compressed format (0x02/0x03 + 32 bytes * 2)
    return publicKey.length >= 64 && 
           publicKey.length <= 130 && 
           /^[0-9a-fA-F]+$/.test(publicKey) &&
           (publicKey.startsWith('04') || publicKey.startsWith('02') || publicKey.startsWith('03'));
  }

  /**
   * Generate a new key pair for voter registration
   */
  generateVoterKeyPair(): { privateKey: string; publicKey: string } {
    return KeyManager.generateKeyPair();
  }
}
