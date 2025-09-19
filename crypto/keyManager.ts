import * as crypto from 'crypto';
import { ec } from 'elliptic';
import { Voter } from '../types';

const elliptic = new ec('secp256k1');

export class KeyManager {
  /**
   * Generate a new key pair for a voter
   */
  static generateKeyPair(): { privateKey: string; publicKey: string } {
    const keyPair = elliptic.genKeyPair();
    const privateKey = keyPair.getPrivate('hex');
    const publicKey = keyPair.getPublic('hex');
    
    return { privateKey, publicKey };
  }

  /**
   * Sign a message with a private key
   */
  static signMessage(message: string, privateKey: string): string {
    const keyPair = elliptic.keyFromPrivate(privateKey, 'hex');
    const msgHash = this.hashMessage(message);
    const signature = keyPair.sign(msgHash);
    return signature.toDER('hex');
  }

  /**
   * Verify a signature with a public key
   */
  static verifySignature(message: string, signature: string, publicKey: string): boolean {
    try {
      const keyPair = elliptic.keyFromPublic(publicKey, 'hex');
      const msgHash = this.hashMessage(message);
      // Verify signature directly (elliptic handles DER format)
      return keyPair.verify(msgHash, signature);
    } catch (error) {
      return false;
    }
  }

  /**
   * Hash a message using SHA-256
   */
  static hashMessage(message: string): string {
    return crypto.createHash('sha256').update(message).digest('hex');
  }

  /**
   * Create a deterministic hash for vote content
   */
  static createVoteHash(candidateId: string, voterId: string, timestamp: number): string {
    const voteData = `${candidateId}:${voterId}:${timestamp}`;
    return this.hashMessage(voteData);
  }

  /**
   * Verify that a public key belongs to a registered voter
   */
  static verifyVoterPublicKey(publicKey: string, voter: Voter): boolean {
    return voter.publicKey === publicKey;
  }
}
