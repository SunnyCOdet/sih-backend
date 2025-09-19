import express from 'express';
import { VoterRegistrationService } from '../../services/voterRegistration';
import { VoteService } from '../../services/voteService';
import { TamperDetectionService } from '../../services/tamperDetection';
import { Blockchain } from '../../blockchain/blockchain';
import { VoteSubmission, VoterRegistration } from '../../types';

const router = express.Router();

// Initialize services
const voterRegistration = new VoterRegistrationService();
const blockchain = new Blockchain();
const tamperDetection = new TamperDetectionService(blockchain);
const voteService = new VoteService(voterRegistration, blockchain);

/**
 * GET /api/voting
 * Get voting system information
 */
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Secure Voting System API',
    version: '1.0.0',
    endpoints: {
      registration: {
        'POST /register': 'Register a new voter',
        'POST /generate-keys': 'Generate key pair for voter',
        'GET /voters': 'Get all registered voters',
        'GET /voter/:voterId': 'Get specific voter info'
      },
      voting: {
        'POST /submit': 'Submit a vote',
        'POST /create-vote': 'Create vote with ZK proof',
        'GET /votes': 'Get all votes',
        'GET /votes/candidate/:candidateId': 'Get votes by candidate',
        'GET /results': 'Get voting results',
        'GET /stats': 'Get comprehensive statistics'
      },
      security: {
        'GET /blockchain/integrity': 'Verify blockchain integrity',
        'GET /tamper-detection/activities': 'Get suspicious activities',
        'GET /tamper-detection/stats': 'Get tamper detection stats'
      }
    }
  });
});

/**
 * POST /api/voting/register
 * Register a new voter
 */
router.post('/register', async (req, res) => {
  try {
    const { voterId, publicKey, registrationData } = req.body as VoterRegistration;
    
    if (!voterId || !publicKey) {
      return res.status(400).json({
        success: false,
        error: 'Voter ID and public key are required'
      });
    }

    const result = voterRegistration.registerVoter({
      voterId,
      publicKey,
      registrationData
    });

    if (result.success) {
      res.status(201).json({
        success: true,
        message: 'Voter registered successfully',
        voter: result.voter
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
});

/**
 * POST /api/voting/generate-keys
 * Generate key pair for voter registration
 */
router.post('/generate-keys', (req, res) => {
  try {
    const keyPair = voterRegistration.generateVoterKeyPair();
    res.json({
      success: true,
      keyPair
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Key generation failed'
    });
  }
});

/**
 * POST /api/voting/submit
 * Submit a vote
 */
router.post('/submit', async (req, res) => {
  try {
    const voteSubmission = req.body as VoteSubmission;
    
    if (!voteSubmission.publicKey || !voteSubmission.voteHash || !voteSubmission.signature ||
        !voteSubmission.zeroKnowledgeProof || !voteSubmission.candidateId) {
      return res.status(400).json({
        success: false,
        error: 'All vote submission fields are required'
      });
    }

    const result = await voteService.submitVote(voteSubmission);
    
    if (result.isValid) {
      res.status(201).json({
        success: true,
        message: 'Vote submitted successfully',
        blockIndex: result.blockIndex
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.reason
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Vote submission failed'
    });
  }
});

/**
 * POST /api/voting/create-vote
 * Create a vote with zero-knowledge proof
 */
router.post('/create-vote', (req, res) => {
  try {
    const { candidateId, voterId, privateKey } = req.body;
    
    if (!candidateId || !voterId || !privateKey) {
      return res.status(400).json({
        success: false,
        error: 'Candidate ID, voter ID, and private key are required'
      });
    }

    const voteData = voteService.createVoteWithProof(candidateId, voterId, privateKey);
    
    res.json({
      success: true,
      voteData
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Vote creation failed'
    });
  }
});

/**
 * GET /api/voting/votes
 * Get all votes (for transparency)
 */
router.get('/votes', (req, res) => {
  try {
    const votes = voteService.getAllVotes();
    res.json({
      success: true,
      votes,
      count: votes.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve votes'
    });
  }
});

/**
 * GET /api/voting/votes/candidate/:candidateId
 * Get votes by candidate
 */
router.get('/votes/candidate/:candidateId', (req, res) => {
  try {
    const { candidateId } = req.params;
    const votes = voteService.getVotesByCandidate(candidateId);
    
    res.json({
      success: true,
      candidateId,
      votes,
      count: votes.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve votes by candidate'
    });
  }
});

/**
 * GET /api/voting/results
 * Get voting results
 */
router.get('/results', (req, res) => {
  try {
    const results = voteService.getVoteCounts();
    res.json({
      success: true,
      results
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve results'
    });
  }
});

/**
 * GET /api/voting/stats
 * Get comprehensive voting statistics
 */
router.get('/stats', (req, res) => {
  try {
    const stats = voteService.getVotingStats();
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve statistics'
    });
  }
});

/**
 * GET /api/voting/voters
 * Get all registered voters
 */
router.get('/voters', (req, res) => {
  try {
    const voters = voterRegistration.getAllVoters();
    res.json({
      success: true,
      voters,
      count: voters.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve voters'
    });
  }
});

/**
 * GET /api/voting/voter/:voterId
 * Get specific voter information
 */
router.get('/voter/:voterId', (req, res) => {
  try {
    const { voterId } = req.params;
    const voter = voterRegistration.getVoter(voterId);
    
    if (voter) {
      res.json({
        success: true,
        voter
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Voter not found'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve voter information'
    });
  }
});

/**
 * GET /api/voting/blockchain/integrity
 * Verify blockchain integrity
 */
router.get('/blockchain/integrity', (req, res) => {
  try {
    const integrity = tamperDetection.verifyBlockchainIntegrity();
    res.json({
      success: true,
      integrity
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to verify blockchain integrity'
    });
  }
});

/**
 * GET /api/voting/tamper-detection/activities
 * Get suspicious activities
 */
router.get('/tamper-detection/activities', (req, res) => {
  try {
    const activities = tamperDetection.getSuspiciousActivities();
    res.json({
      success: true,
      activities
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve suspicious activities'
    });
  }
});

/**
 * GET /api/voting/tamper-detection/stats
 * Get tamper detection statistics
 */
router.get('/tamper-detection/stats', (req, res) => {
  try {
    const stats = tamperDetection.getTamperStats();
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve tamper detection statistics'
    });
  }
});

export default router;
