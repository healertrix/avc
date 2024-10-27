const crypto = require('crypto');
const express = require('express');
const WebSocket = require('ws');
const bodyParser = require('body-parser');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const fs = require('fs').promises;
const path = require('path');
const Redis = require('ioredis');

// Initialize Redis client
const redisClient = new Redis(
  'rediss://default:Aa8gAAIjcDE3YjRlYTc1NWY1MjQ0MWY0OTczOTQ5NDY3OTIzMzJkNnAxMA@sunny-cicada-44832.upstash.io:6379'
);

class Block {
  constructor(index, timestamp, transactions, previousHash = '', forger = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.hash = this.calculateHash();
    this.nonce = 0;
    this.forger = forger;
  }

  calculateHash() {
    return crypto
      .createHash('sha256')
      .update(
        this.index +
          this.previousHash +
          this.timestamp +
          JSON.stringify(this.transactions) +
          this.nonce
      )
      .digest('hex');
  }

  mineBlock(difficulty) {
    while (
      this.hash.substring(0, difficulty) !== Array(difficulty + 1).join('0')
    ) {
      this.nonce++;
      this.hash = this.calculateHash();
    }
    console.log('Block mined: ' + this.hash);
  }
}

class Wallet {
  constructor() {
    this.keyPair = ec.genKeyPair();
    this.publicKey = this.keyPair.getPublic('hex');
    this.privateKey = this.keyPair.getPrivate('hex');
  }

  sign(dataHash) {
    return this.keyPair.sign(dataHash).toDER('hex');
  }
}

class Transaction {
  constructor(
    fromAddress,
    toAddress,
    amount,
    fee = 0,
    type = 'transfer',
    nftData = null
  ) {
    this.fromAddress = fromAddress;
    this.toAddress = toAddress;
    this.amount = amount;
    this.timestamp = Date.now();
    this.signature = null;
    this.fee = fee;
    this.type = type; // 'transfer', 'mintNFT', or 'transferNFT'
    this.nftData = nftData;
  }

  calculateHash() {
    return crypto
      .createHash('sha256')
      .update(this.fromAddress + this.toAddress + this.amount + this.timestamp)
      .digest('hex');
  }

  signTransaction(signingKey) {
    if (signingKey.getPublic('hex') !== this.fromAddress) {
      throw new Error('You cannot sign transactions for other wallets!');
    }

    const hashTx = this.calculateHash();
    const sig = signingKey.sign(hashTx, 'base64');
    this.signature = sig.toDER('hex');
  }

  isValid() {
    if (this.fromAddress === null) return true; // For mining rewards and NFT minting

    if (!this.signature || this.signature.length === 0) {
      throw new Error('No signature in this transaction');
    }

    const publicKey = ec.keyFromPublic(this.fromAddress, 'hex');
    return publicKey.verify(this.calculateHash(), this.signature);
  }
}

class Mempool {
  constructor() {
    this.transactions = [];
  }

  async addTransaction(transaction) {
    this.transactions.push(transaction);
    await redisClient.rpush('mempool', JSON.stringify(transaction));
  }

  async getTransactions(limit) {
    const transactions = await redisClient.lrange('mempool', 0, limit - 1);
    return transactions.map((tx) => JSON.parse(tx));
  }

  async removeTransactions(transactions) {
    for (const tx of transactions) {
      await redisClient.lrem('mempool', 0, JSON.stringify(tx));
    }
    this.transactions = this.transactions.filter(
      (tx) => !transactions.find((t) => t.id === tx.id)
    );
  }
}

class NFT {
  constructor(tokenId, owner, metadata) {
    this.tokenId = tokenId;
    this.owner = owner;
    this.metadata = metadata;
  }
}

class Blockchain {
  constructor() {
    this.chain = [];
    this.difficulty = 4;
    this.pendingTransactions = [];
    this.miningReward = 10;
    this.mempool = new Mempool();
    this.blockTime = 10000; // Target block time in milliseconds
    this.contracts = new Map();
    this.minFee = 0.001; // Minimum transaction fee
    this.nfts = new Map();
    this.nftMintingFee = 1; // Set a fee for minting NFTs
    this.initializeChain();
  }

  async initializeChain() {
    const storedChain = await redisClient.get('blockchain');
    if (storedChain) {
      this.chain = JSON.parse(storedChain);
    } else {
      this.chain = [this.createGenesisBlock()];
      await this.saveChain();
    }
  }

  async saveChain() {
    await redisClient.set('blockchain', JSON.stringify(this.chain));
  }

  createGenesisBlock() {
    return new Block(0, Date.now(), [], '0', '0');
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  async createBlock(forger) {
    const transactions = await this.mempool.getTransactions(10);
    const fees = transactions.reduce((sum, tx) => sum + tx.fee, 0);

    // Calculate additional reward for NFT transactions
    const nftTransactions = transactions.filter(
      (tx) => tx.type === 'mintNFT' || tx.type === 'transferNFT'
    );
    const nftReward = nftTransactions.length * 0.1; // Additional 0.1 coin reward per NFT transaction

    const rewardTransaction = new Transaction(
      null,
      forger,
      this.miningReward + fees + nftReward
    );
    transactions.push(rewardTransaction);

    const newBlock = new Block(
      this.chain.length,
      Date.now(),
      transactions,
      this.getLatestBlock().hash,
      forger
    );
    newBlock.mineBlock(this.difficulty);
    this.chain.push(newBlock);
    await this.saveChain();
    await this.mempool.removeTransactions(transactions);
    this.adjustDifficulty();
    return newBlock;
  }

  async addTransaction(transaction) {
    if (!transaction.fromAddress && transaction.type !== 'mintNFT') {
      throw new Error(
        'Transaction must include from address (except for NFT minting)'
      );
    }

    if (!transaction.toAddress) {
      throw new Error('Transaction must include to address');
    }

    if (!transaction.isValid()) {
      throw new Error('Cannot add invalid transaction to chain');
    }

    if (transaction.type === 'transfer' && transaction.amount <= 0) {
      throw new Error('Transaction amount should be higher than 0');
    }

    if (transaction.type === 'transfer') {
      const walletBalance = await this.getBalanceOfAddress(
        transaction.fromAddress
      );
      if (walletBalance < transaction.amount + transaction.fee) {
        throw new Error('Not enough balance');
      }

      if (transaction.fee < this.minFee) {
        throw new Error(`Transaction fee must be at least ${this.minFee}`);
      }
    }

    await this.mempool.addTransaction(transaction);
  }

  async getBalanceOfAddress(address) {
    let balance = 0;

    for (const block of this.chain) {
      for (const trans of block.transactions) {
        if (trans.fromAddress === address) {
          balance -= trans.amount;
          balance -= trans.fee; // Deduct the fee from the sender
        }

        if (trans.toAddress === address) {
          balance += trans.amount;
        }
      }
    }

    return balance;
  }

  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false;
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }
    return true;
  }

  getNextForger(timestamp) {
    const stakeholders = this.getStakeholders();
    const forgerIndex = timestamp % stakeholders.length;
    return stakeholders[forgerIndex];
  }

  getStakeholders() {
    const stakeholders = [];
    for (const block of this.chain) {
      for (const transaction of block.transactions) {
        if (!stakeholders.includes(transaction.toAddress)) {
          stakeholders.push(transaction.toAddress);
        }
      }
    }
    return stakeholders;
  }

  adjustDifficulty() {
    const latestBlock = this.getLatestBlock();
    const prevBlock = this.chain[this.chain.length - 2];
    const timeExpected = this.blockTime * (this.chain.length - 1);
    const timeActual = latestBlock.timestamp - this.chain[0].timestamp;

    if (timeActual < timeExpected / 2) {
      this.difficulty++;
    } else if (timeActual > timeExpected * 2) {
      this.difficulty = Math.max(1, this.difficulty - 1);
    }
  }

  async deployContract(address, code) {
    this.contracts.set(address, new SmartContract(code));
    await redisClient.hset('contracts', address, code);
  }

  async executeContract(contractAddress, transaction) {
    const contractCode = await redisClient.hget('contracts', contractAddress);
    if (!contractCode) {
      throw new Error('Contract not found');
    }
    const contract = new SmartContract(contractCode);
    return contract.execute(transaction, this);
  }

  async mintNFT(owner, metadata, fee) {
    if (fee < this.nftMintingFee) {
      throw new Error(`NFT minting fee must be at least ${this.nftMintingFee}`);
    }

    const tokenId = crypto.randomBytes(32).toString('hex');
    const nftTransaction = new Transaction(null, owner, 0, fee, 'mintNFT', {
      tokenId,
      metadata,
    });
    await this.addTransaction(nftTransaction);
    return tokenId;
  }

  async transferNFT(tokenId, fromAddress, toAddress, privateKey) {
    const nft = this.getNFT(tokenId);
    if (!nft) {
      throw new Error('NFT not found');
    }
    if (nft.owner !== fromAddress) {
      throw new Error('Not the owner of the NFT');
    }

    const wallet = new Wallet();
    wallet.privateKey = privateKey;
    wallet.publicKey = ec.keyFromPrivate(privateKey).getPublic('hex');

    if (wallet.publicKey !== fromAddress) {
      throw new Error('Invalid private key for the given address');
    }

    const nftTransaction = new Transaction(
      fromAddress,
      toAddress,
      0,
      0,
      'transferNFT',
      { tokenId }
    );
    nftTransaction.signTransaction(wallet.keyPair);
    await this.mempool.addTransaction(nftTransaction);
  }

  getNFT(tokenId) {
    for (const block of this.chain) {
      for (const tx of block.transactions) {
        if (tx.type === 'mintNFT' && tx.nftData.tokenId === tokenId) {
          return {
            tokenId,
            owner: tx.toAddress,
            metadata: tx.nftData.metadata,
          };
        }
        if (tx.type === 'transferNFT' && tx.nftData.tokenId === tokenId) {
          return {
            tokenId,
            owner: tx.toAddress,
            metadata: this.getNFT(tokenId).metadata,
          };
        }
      }
    }
    return null;
  }

  getNFTsByOwner(owner) {
    const ownedNFTs = [];
    for (const block of this.chain) {
      for (const tx of block.transactions) {
        if (tx.type === 'mintNFT' && tx.toAddress === owner) {
          ownedNFTs.push(this.getNFT(tx.nftData.tokenId));
        } else if (tx.type === 'transferNFT') {
          const nft = this.getNFT(tx.nftData.tokenId);
          if (nft && nft.owner === owner) {
            ownedNFTs.push(nft);
          }
        }
      }
    }
    return ownedNFTs;
  }
}

class MultiSigTransaction extends Transaction {
  constructor(fromAddresses, toAddress, amount, requiredSignatures) {
    super(null, toAddress, amount);
    this.fromAddresses = fromAddresses;
    this.requiredSignatures = requiredSignatures;
    this.signatures = [];
  }

  addSignature(address, signature) {
    if (
      this.fromAddresses.includes(address) &&
      !this.signatures.find((s) => s.address === address)
    ) {
      this.signatures.push({ address, signature });
    }
  }

  isValid() {
    if (this.signatures.length < this.requiredSignatures) {
      return false;
    }

    return this.signatures.every(({ address, signature }) => {
      const publicKey = ec.keyFromPublic(address, 'hex');
      return publicKey.verify(this.calculateHash(), signature);
    });
  }
}

class SmartContract {
  constructor(code) {
    this.code = code;
  }

  execute(transaction, blockchain) {
    const context = {
      transaction,
      blockchain,
      balanceOf: (address) => blockchain.getBalanceOfAddress(address),
    };

    return new Function('context', `with(context){${this.code}}`)(context);
  }
}

class WalletManager {
  constructor() {
    this.walletDir = path.join(__dirname, 'wallets');
    this.initializeWalletDir();
  }

  async initializeWalletDir() {
    try {
      await fs.access(this.walletDir);
    } catch (error) {
      if (error.code === 'ENOENT') {
        await fs.mkdir(this.walletDir);
      } else {
        throw error;
      }
    }
  }

  async createWallet(wallet) {
    const filename = path.join(this.walletDir, `${wallet.publicKey}.json`);
    await fs.writeFile(
      filename,
      JSON.stringify({
        publicKey: wallet.publicKey,
        privateKey: wallet.privateKey,
      })
    );
    return wallet.publicKey;
  }

  async getWallet(publicKey) {
    const filename = path.join(this.walletDir, `${publicKey}.json`);
    try {
      const data = await fs.readFile(filename, 'utf8');
      const walletData = JSON.parse(data);
      const wallet = new Wallet();
      wallet.publicKey = walletData.publicKey;
      wallet.privateKey = walletData.privateKey;
      return wallet;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }
}

const walletManager = new WalletManager();

class P2pServer {
  constructor(blockchain) {
    this.blockchain = blockchain;
    this.sockets = [];
    this.peers = new Set();
    this.nodeId = uuidv4();
  }

  listen(port) {
    const server = new WebSocket.Server({ port });
    server.on('connection', (socket) => this.connectSocket(socket));
    console.log(`Listening for peer-to-peer connections on port ${port}`);
  }

  connectToPeers(newPeers) {
    newPeers.forEach((peer) => {
      if (!this.peers.has(peer)) {
        const socket = new WebSocket(peer);
        socket.on('open', () => this.connectSocket(socket));
        this.peers.add(peer);
      }
    });
  }

  connectSocket(socket) {
    this.sockets.push(socket);
    console.log('Socket connected');

    this.messageHandler(socket);
    this.sendChain(socket);
    this.broadcastPeer(
      socket._socket.remoteAddress + ':' + socket._socket.remotePort
    );
  }

  messageHandler(socket) {
    socket.on('message', (message) => {
      const data = JSON.parse(message);
      switch (data.type) {
        case 'CHAIN':
          this.blockchain.replaceChain(data.chain);
          break;
        case 'TRANSACTION':
          this.blockchain.addTransaction(data.transaction);
          break;
        case 'PEER':
          this.connectToPeers([data.peer]);
          break;
      }
    });
  }

  sendChain(socket) {
    socket.send(
      JSON.stringify({
        type: 'CHAIN',
        chain: this.blockchain.chain,
      })
    );
  }

  syncChains() {
    this.sockets.forEach((socket) => this.sendChain(socket));
  }

  broadcastTransaction(transaction) {
    this.sockets.forEach((socket) => {
      socket.send(
        JSON.stringify({
          type: 'TRANSACTION',
          transaction,
        })
      );
    });
  }

  broadcastPeer(peer) {
    this.sockets.forEach((socket) => {
      socket.send(
        JSON.stringify({
          type: 'PEER',
          peer,
        })
      );
    });
  }
}

// Initialize blockchain
const simpleCoin = new Blockchain();

// Set up Express server
const app = express();
app.use(bodyParser.json());
const cors = require('cors');
app.use(cors());
// Serve static files
app.use(express.static('public'));

// API endpoints
app.get('/api/blockchain', async (req, res) => {
  res.json(simpleCoin.chain);
});

// Add input validation middleware
const validateTransaction = [
  body('fromAddress').isString().notEmpty(),
  body('toAddress').isString().notEmpty(),
  body('amount').isFloat({ min: 0.00000001 }),
  body('privateKey').isString().notEmpty(),
];

const validateMultiSigTransaction = [
  body('fromAddresses').isArray().notEmpty(),
  body('toAddress').isString().notEmpty(),
  body('amount').isFloat({ min: 0.00000001 }),
  body('requiredSignatures').isInt({ min: 1 }),
  body('signatures').isArray().notEmpty(),
];

const validateContractDeployment = [
  body('address').isString().notEmpty(),
  body('code').isString().notEmpty(),
];

const validateContractExecution = [
  body('contractAddress').isString().notEmpty(),
  body('transaction').isObject().notEmpty(),
];

// Update API endpoints to use validation middleware
app.post('/api/transaction', validateTransaction, async (req, res) => {
  const { fromAddress, toAddress, amount, privateKey, fee } = req.body;
  try {
    const wallet = new Wallet();
    wallet.privateKey = privateKey;
    wallet.publicKey = ec.keyFromPrivate(privateKey).getPublic('hex');

    const transaction = new Transaction(
      wallet.publicKey,
      toAddress,
      amount,
      fee
    );
    transaction.signTransaction(ec.keyFromPrivate(privateKey));

    await simpleCoin.addTransaction(transaction);
    res.json({ message: 'Transaction added to pending transactions.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/mine', async (req, res) => {
  const { minerAddress } = req.body;
  const newBlock = await simpleCoin.createBlock(minerAddress);
  res.json({ message: 'Block mined successfully.', block: newBlock });
});

app.get('/api/balance/:address', async (req, res) => {
  const balance = await simpleCoin.getBalanceOfAddress(req.params.address);
  res.json({ balance });
});

app.post('/api/forge', async (req, res) => {
  const { forgerAddress } = req.body;
  const nextForger = simpleCoin.getNextForger(Date.now());
  if (forgerAddress === nextForger) {
    const newBlock = await simpleCoin.createBlock(forgerAddress);
    res.json({ message: 'Block forged successfully.', block: newBlock });
  } else {
    res.status(403).json({ error: 'Not authorized to forge at this time.' });
  }
});

// Add a new API endpoint for multi-signature transactions
app.post('/api/multisig-transaction', (req, res) => {
  const { fromAddresses, toAddress, amount, requiredSignatures, signatures } =
    req.body;
  try {
    const transaction = new MultiSigTransaction(
      fromAddresses,
      toAddress,
      amount,
      requiredSignatures
    );
    signatures.forEach(({ address, signature }) => {
      transaction.addSignature(address, signature);
    });

    if (transaction.isValid()) {
      simpleCoin.addTransaction(transaction);
      res.json({
        message: 'Multi-signature transaction added to pending transactions.',
      });
    } else {
      throw new Error('Invalid multi-signature transaction');
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Add API endpoints for deploying and executing smart contracts
app.post('/api/deploy-contract', (req, res) => {
  const { address, code } = req.body;
  try {
    simpleCoin.deployContract(address, code);
    res.json({ message: 'Smart contract deployed successfully.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/execute-contract', (req, res) => {
  const { contractAddress, transaction } = req.body;
  try {
    const result = simpleCoin.executeContract(contractAddress, transaction);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Add API endpoints for wallet management
app.post('/api/create-wallet', async (req, res) => {
  try {
    const wallet = new Wallet();
    await walletManager.createWallet(wallet);
    res.json({
      publicKey: wallet.publicKey,
      privateKey: wallet.privateKey,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/wallet/:publicKey', async (req, res) => {
  try {
    const wallet = await walletManager.getWallet(req.params.publicKey);
    if (wallet) {
      res.json({ publicKey: wallet.publicKey });
    } else {
      res.status(404).json({ error: 'Wallet not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add new API endpoints for NFT operations
app.post('/api/mint-nft', async (req, res) => {
  const { owner, metadata, fee } = req.body;

  try {
    if (typeof fee !== 'number' || fee < simpleCoin.nftMintingFee) {
      throw new Error(
        `NFT minting fee must be at least ${simpleCoin.nftMintingFee}`
      );
    }

    const tokenId = await simpleCoin.mintNFT(owner, metadata, parseFloat(fee));
    res.json({ message: 'NFT minting transaction added to mempool', tokenId });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/transfer-nft', async (req, res) => {
  const { tokenId, fromAddress, toAddress, privateKey } = req.body;
  try {
    await simpleCoin.transferNFT(tokenId, fromAddress, toAddress, privateKey);
    res.json({ message: 'NFT transfer transaction added to mempool' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/nft/:tokenId', (req, res) => {
  try {
    const nft = simpleCoin.getNFT(req.params.tokenId);
    if (nft) {
      res.json(nft);
    } else {
      res.status(404).json({ error: 'NFT not found' });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/nfts/:owner', (req, res) => {
  try {
    const nfts = simpleCoin.getNFTsByOwner(req.params.owner);
    res.json(nfts);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Initialize P2P server
const p2pServer = new P2pServer(simpleCoin);
p2pServer.listen(6001);

// Start the server
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// At the end of simplecoin.js
if (typeof window !== 'undefined') {
  window.SimpleCoin = SimpleCoin;
}
