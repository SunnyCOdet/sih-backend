import { VoterRegistrationService } from '../services/voterRegistration';
import { VoteService } from '../services/voteService';
import { TamperDetectionService } from '../services/tamperDetection';
import { Blockchain } from '../blockchain/blockchain';
import { KeyManager } from '../crypto/keyManager';
import { ZeroKnowledgeProofSystem } from '../crypto/zeroKnowledgeProof';

/**
 * Example usage of the secure voting system
 */
async function demonstrateVotingSystem() {
  console.log('🗳️  Secure Voting System Demo\n');

  // Initialize services
  const voterRegistration = new VoterRegistrationService();
  const blockchain = new Blockchain();
  const tamperDetection = new TamperDetectionService(blockchain);
  const voteService = new VoteService(voterRegistration, blockchain);

  // Step 1: Voter Registration
  console.log('1. Voter Registration');
  console.log('===================');
  
  const voter1KeyPair = voterRegistration.generateVoterKeyPair();
  const voter2KeyPair = voterRegistration.generateVoterKeyPair();
  
  const voter1 = voterRegistration.registerVoter({
    voterId: 'voter-001',
    publicKey: voter1KeyPair.publicKey,
    registrationData: { name: 'Alice Johnson', district: 'District A' }
  });

  const voter2 = voterRegistration.registerVoter({
    voterId: 'voter-002',
    publicKey: voter2KeyPair.publicKey,
    registrationData: { name: 'Bob Smith', district: 'District B' }
  });

  console.log('✅ Voter 1 registered:', voter1.success ? 'Success' : voter1.error);
  console.log('✅ Voter 2 registered:', voter2.success ? 'Success' : voter2.error);
  console.log('');

  // Step 2: Vote Creation with Zero-Knowledge Proof
  console.log('2. Vote Creation with Zero-Knowledge Proof');
  console.log('==========================================');
  
  const candidateA = 'candidate-alice';
  const candidateB = 'candidate-bob';
  
  // Create votes with ZK proofs
  const vote1Data = voteService.createVoteWithProof(
    candidateA,
    'voter-001',
    voter1KeyPair.privateKey
  );
  
  const vote2Data = voteService.createVoteWithProof(
    candidateB,
    'voter-002',
    voter2KeyPair.privateKey
  );

  console.log('✅ Vote 1 created with ZK proof');
  console.log('   Vote Hash:', vote1Data.voteHash.substring(0, 20) + '...');
  console.log('   ZK Proof:', vote1Data.zeroKnowledgeProof.substring(0, 20) + '...');
  console.log('   Signature:', vote1Data.signature.substring(0, 20) + '...');
  console.log('');

  // Step 3: Vote Submission
  console.log('3. Vote Submission');
  console.log('==================');
  
  const voteSubmission1 = {
    publicKey: voter1KeyPair.publicKey,
    voteHash: vote1Data.voteHash,
    signature: vote1Data.signature,
    zeroKnowledgeProof: vote1Data.zeroKnowledgeProof,
    candidateId: candidateA
  };

  const voteSubmission2 = {
    publicKey: voter2KeyPair.publicKey,
    voteHash: vote2Data.voteHash,
    signature: vote2Data.signature,
    zeroKnowledgeProof: vote2Data.zeroKnowledgeProof,
    candidateId: candidateB
  };

  const result1 = await voteService.submitVote(voteSubmission1);
  const result2 = await voteService.submitVote(voteSubmission2);

  console.log('✅ Vote 1 submission:', result1.isValid ? 'Success' : result1.reason);
  console.log('✅ Vote 2 submission:', result2.isValid ? 'Success' : result2.reason);
  
  // Force mine pending votes for demo
  blockchain.forceMineBlock();
  console.log('⛏️  Pending votes mined into blockchain');
  console.log('');

  // Step 4: Tampering Attempt Detection
  console.log('4. Tampering Attempt Detection');
  console.log('==============================');
  
  // Simulate a tampering attempt
  const fakeVote = {
    id: 'fake-vote-001',
    voterId: 'voter-001', // Same voter trying to vote again
    candidateId: 'candidate-charlie',
    voteHash: 'fake-hash',
    signature: 'fake-signature',
    zeroKnowledgeProof: 'fake-proof',
    timestamp: new Date()
  };

  const tamperResult = tamperDetection.detectTampering(fakeVote, voter1KeyPair.publicKey);
  console.log('🚨 Tampering attempt detected:', !tamperResult.isValid ? 'Yes' : 'No');
  console.log('   Reason:', tamperResult.reason);
  console.log('');

  // Step 5: Results and Verification
  console.log('5. Results and Verification');
  console.log('===========================');
  
  const allVotes = voteService.getAllVotes();
  const voteCounts = voteService.getVoteCounts();
  const blockchainInfo = blockchain.getBlockchainInfo();
  const voterStats = voterRegistration.getVoterStats();

  console.log('📊 Vote Counts:');
  Object.entries(voteCounts).forEach(([candidate, count]) => {
    console.log(`   ${candidate}: ${count} votes`);
  });
  
  console.log('\n🔗 Blockchain Info:');
  console.log(`   Chain Length: ${blockchainInfo.chainLength}`);
  console.log(`   Total Votes: ${blockchainInfo.totalVotes}`);
  console.log(`   Pending Votes: ${blockchainInfo.pendingVotes}`);
  console.log(`   Last Block Hash: ${blockchainInfo.lastBlockHash.substring(0, 20)}...`);
  
  console.log('\n👥 Voter Stats:');
  console.log(`   Total Voters: ${voterStats.total}`);
  console.log(`   Voted: ${voterStats.voted}`);
  console.log(`   Remaining: ${voterStats.remaining}`);
  console.log('');

  // Step 6: Blockchain Integrity Verification
  console.log('6. Blockchain Integrity Verification');
  console.log('====================================');
  
  const integrityCheck = tamperDetection.verifyBlockchainIntegrity();
  console.log('🔒 Blockchain Integrity:', integrityCheck.isIntact ? 'Intact' : 'Compromised');
  
  if (!integrityCheck.isIntact) {
    console.log('⚠️  Issues detected:');
    integrityCheck.issues.forEach(issue => console.log(`   - ${issue}`));
  }
  
  console.log('');

  // Step 7: Tamper Detection Statistics
  console.log('7. Tamper Detection Statistics');
  console.log('==============================');
  
  const tamperStats = tamperDetection.getTamperStats();
  console.log('🛡️  Tamper Detection Stats:');
  console.log(`   Total Activities: ${tamperStats.totalActivities}`);
  console.log(`   Recent Activities: ${tamperStats.recentActivities}`);
  console.log('   By Severity:');
  Object.entries(tamperStats.bySeverity).forEach(([severity, count]) => {
    console.log(`     ${severity}: ${count}`);
  });
  
  console.log('\n✅ Demo completed successfully!');
}

// Run the demo
if (require.main === module) {
  demonstrateVotingSystem().catch(console.error);
}

export { demonstrateVotingSystem };
