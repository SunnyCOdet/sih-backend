import * as fs from 'fs';
import * as path from 'path';

export interface StoredData {
  voters: Record<string, any>;
  publicKeys: string[];
  votes: Record<string, any>;
  blocks: any[];
  lastUpdated: string;
}

export class DataPersistence {
  private dataFile: string;
  private data: StoredData;

  constructor(dataFile: string = 'voting-data.json') {
    this.dataFile = path.join(process.cwd(), 'data', dataFile);
    this.data = this.loadData();
  }

  private loadData(): StoredData {
    try {
      // Ensure data directory exists
      const dataDir = path.dirname(this.dataFile);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      if (fs.existsSync(this.dataFile)) {
        const fileContent = fs.readFileSync(this.dataFile, 'utf8');
        return JSON.parse(fileContent);
      }
    } catch (error) {
      console.error('Error loading data:', error);
    }

    // Return default empty data structure
    return {
      voters: {},
      publicKeys: [],
      votes: {},
      blocks: [],
      lastUpdated: new Date().toISOString()
    };
  }

  private saveData(): void {
    try {
      this.data.lastUpdated = new Date().toISOString();
      fs.writeFileSync(this.dataFile, JSON.stringify(this.data, null, 2));
    } catch (error) {
      console.error('Error saving data:', error);
    }
  }

  // Voter management
  saveVoter(voterId: string, voter: any): void {
    this.data.voters[voterId] = voter;
    this.saveData();
  }

  getVoter(voterId: string): any | null {
    return this.data.voters[voterId] || null;
  }

  getAllVoters(): any[] {
    return Object.values(this.data.voters);
  }

  deleteVoter(voterId: string): boolean {
    if (this.data.voters[voterId]) {
      delete this.data.voters[voterId];
      this.saveData();
      return true;
    }
    return false;
  }

  // Public key management
  addPublicKey(publicKey: string): void {
    if (!this.data.publicKeys.includes(publicKey)) {
      this.data.publicKeys.push(publicKey);
      this.saveData();
    }
  }

  hasPublicKey(publicKey: string): boolean {
    return this.data.publicKeys.includes(publicKey);
  }

  removePublicKey(publicKey: string): boolean {
    const index = this.data.publicKeys.indexOf(publicKey);
    if (index > -1) {
      this.data.publicKeys.splice(index, 1);
      this.saveData();
      return true;
    }
    return false;
  }

  // Vote management
  saveVote(voteId: string, vote: any): void {
    this.data.votes[voteId] = vote;
    this.saveData();
  }

  getVote(voteId: string): any | null {
    return this.data.votes[voteId] || null;
  }

  getAllVotes(): any[] {
    return Object.values(this.data.votes);
  }

  getVotesByCandidate(candidateId: string): any[] {
    return Object.values(this.data.votes).filter((vote: any) => vote.candidateId === candidateId);
  }

  // Block management
  saveBlock(block: any): void {
    this.data.blocks.push(block);
    this.saveData();
  }

  getAllBlocks(): any[] {
    return this.data.blocks;
  }

  getLastBlock(): any | null {
    return this.data.blocks.length > 0 ? this.data.blocks[this.data.blocks.length - 1] : null;
  }

  // Statistics
  getStats(): any {
    const voters = this.getAllVoters();
    const votes = this.getAllVotes();
    const votedCount = voters.filter((v: any) => v.hasVoted).length;

    return {
      totalVoters: voters.length,
      totalVotes: votes.length,
      votedVoters: votedCount,
      remainingVoters: voters.length - votedCount,
      lastUpdated: this.data.lastUpdated
    };
  }

  // Backup and restore
  backup(): string {
    const backupData = {
      ...this.data,
      backupDate: new Date().toISOString()
    };
    return JSON.stringify(backupData, null, 2);
  }

  restore(backupData: string): boolean {
    try {
      const parsed = JSON.parse(backupData);
      this.data = parsed;
      this.saveData();
      return true;
    } catch (error) {
      console.error('Error restoring data:', error);
      return false;
    }
  }

  // Clear all data
  clearAll(): void {
    this.data = {
      voters: {},
      publicKeys: [],
      votes: {},
      blocks: [],
      lastUpdated: new Date().toISOString()
    };
    this.saveData();
  }
}
