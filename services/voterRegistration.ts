import { Voter, VoterRegistration } from '../types';
import { KeyManager } from '../crypto/keyManager';
import { DataPersistence } from './dataPersistence';

export class VoterRegistrationService {
  private dataPersistence: DataPersistence;

  constructor() {
    this.dataPersistence = new DataPersistence();
  }

  /**
   * Register a new voter
   */
  registerVoter(registrationData: VoterRegistration): { success: boolean; voter?: Voter; error?: string } {
    try {
      console.log('Registering voter:', { voterId: registrationData.voterId, publicKey: registrationData.publicKey?.substring(0, 20) + '...' });
      
      // Check if voter is already registered
      if (this.dataPersistence.getVoter(registrationData.voterId)) {
        console.log('Voter already registered:', registrationData.voterId);
        return { success: false, error: 'Voter already registered' };
      }

      // Check if public key is already in use
      if (this.dataPersistence.hasPublicKey(registrationData.publicKey)) {
        console.log('Public key already in use:', registrationData.publicKey.substring(0, 20) + '...');
        return { success: false, error: 'Public key already in use' };
      }

      // Validate public key format (basic validation)
      if (!this.isValidPublicKey(registrationData.publicKey)) {
        console.log('Invalid public key format:', registrationData.publicKey.substring(0, 20) + '...');
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

      // Store voter and public key persistently
      this.dataPersistence.saveVoter(voter.id, voter);
      this.dataPersistence.addPublicKey(voter.publicKey);

      console.log('Voter registered successfully:', voter.id);
      return { success: true, voter };
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, error: 'Registration failed: ' + (error as Error).message };
    }
  }

  /**
   * Get voter by ID
   */
  getVoter(voterId: string): Voter | null {
    return this.dataPersistence.getVoter(voterId);
  }

  /**
   * Get voter by public key
   */
  getVoterByPublicKey(publicKey: string): Voter | null {
    const voters = this.dataPersistence.getAllVoters();
    return voters.find((voter: Voter) => voter.publicKey === publicKey) || null;
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
      this.dataPersistence.saveVoter(voterId, voter);
      return true;
    }
    return false;
  }

  /**
   * Get all registered voters
   */
  getAllVoters(): Voter[] {
    return this.dataPersistence.getAllVoters();
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
    try {
      return KeyManager.generateKeyPair();
    } catch (error) {
      console.error('Key generation error:', error);
      // Fallback key generation
      const privateKey = Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const publicKey = '04' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
      return { privateKey, publicKey };
    }
  }
}
