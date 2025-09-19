export interface Voter {
  id: string;
  publicKey: string;
  isRegistered: boolean;
  hasVoted: boolean;
  registrationDate: Date;
}

export interface Vote {
  id: string;
  voterId: string;
  candidateId: string;
  voteHash: string;
  signature: string;
  zeroKnowledgeProof: string;
  timestamp: Date;
  blockIndex?: number;
  publicKey?: string;
}

export interface Block {
  index: number;
  timestamp: Date;
  previousHash: string;
  hash: string;
  votes: Vote[];
  merkleRoot: string;
}

export interface VoteSubmission {
  publicKey: string;
  voteHash: string;
  signature: string;
  zeroKnowledgeProof: string;
  candidateId: string;
}

export interface ZeroKnowledgeProof {
  commitment: string;
  proof: string;
  publicInputs: string[];
}

export interface VoterRegistration {
  voterId: string;
  publicKey: string;
  registrationData: any;
}

export interface VoteVerificationResult {
  isValid: boolean;
  reason?: string;
  blockIndex?: number;
}
