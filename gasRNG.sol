// SPDX-License-Identifier: MIT
// compiler version must be greater than or equal to 0.8.20 and less than 0.9.0
pragma solidity ^0.8.20;

contract gasRNG {
    // for now it's hardcoded for easy testing, then we should create a constructor
    address public dealer;
    uint public constant d = 1 ether; // register deposit
    uint public constant d_star = 0.5 ether; // challenging commitment
    uint public constant d_prime = 0.5 ether; // session deposit by dealer

    uint public dealer_funds = 0; 
    bool public dealer_funds_partly_frozen; 

    uint public constant t1 = 2 minutes;
    uint public constant t2 = 2 minutes;
    uint public constant t3 = 2 minutes;
    uint public constant t4 = 2 minutes;
    uint public constant t5 = 2 minutes;
    uint public constant t6 = 2 minutes;
    uint public constant t7 = 2 minutes;
    uint public constant t8 = 2 minutes;
    uint public constant t9 = 2 minutes;
    uint public constant t10 = 2 minutes;
    uint public constant t11 = 2 minutes;
    uint public constant t12 = 2 minutes;
    uint public constant t13 = 2 minutes;
    uint public constant t14 = 2 minutes;

    uint public rho = 1 ether; // session reward

    // bytes32 public root_T_c; // root of the merkle tree commit
    // bytes32 public root_T; // root of the merkle tree final

    uint public n = 0; // number of participants

    constructor() {
        dealer = msg.sender;
    }

    struct Participant {
        bool registered;
        uint index;
        uint deposit;
        uint reward_withdrawn;
        bytes32 commit;
        bool deposit_frozen;
        bool deposit_partly_frozen;
        uint reward;
    }

    mapping(address => Participant) public participants;
    mapping(address => bool) public challenged_participants;
    mapping(address => address) public challenging_participants;

    struct Session {
        bool active;
        uint reward;
        uint start_time;
        uint dealer_deposit;
        bytes32 root_T_c; // root of the merkle tree commit
        bytes32 root_T; // root of the merkle tree final
    }

    Session public session = Session(false, 0, 0, 0, 0, 0);

    uint public dealer_cheating_rewards = 0; 
    uint public session_rewards = 0; 

    modifier deposit_paid_register() {
        require(msg.value >= d, "Deposit must be paid.");
        _;
    }

    modifier not_registered() {
        require(!participants[msg.sender].registered, "Participant is already registered.");
        _;
    }

    modifier registered() {
        require(participants[msg.sender].registered, "Participant is not registered.");
        _;
    }


    modifier deposit_and_reward_paid_session() {
        require(msg.value >= rho + d_prime, "Deposit and rewards must be paid.");
        _;
    }

    modifier only_dealer() {
        require(msg.sender == dealer, "Only dealer can call the function.");
        _;
    }

    modifier only_participants() {
        require(msg.sender != dealer, "Only participants can call the function.");
        _;
    }

    // modifier reward_paid() {
    //     require(msg.value >= rho, "Reward must be paid.");
    //     _;
    // }

    modifier no_active_session() {
        require(!session.active, "There is an active session.");
        _;
    }

    modifier active_session() {
        require(session.active, "There is no active session in progress.");
        _;
    }

    modifier funds_not_frozen() {
        require(!participants[msg.sender].deposit_frozen, "Deposit is frozen.");
        _;
    }

    modifier funds_frozen() {
        require(participants[msg.sender].deposit_frozen, "Deposit is not frozen.");
        _;
    }

    modifier not_challenged(address _addr) {
        require(!challenged_participants[_addr], "Participant is already challenged.");
        _;
    }


    modifier t2_in_progress() {
        require(block.timestamp > session.start_time + t1 && block.timestamp <=session.start_time + t1 + t2, "Must be t2 period.");
        _;
    }

    modifier t3_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 && block.timestamp <=session.start_time + t1 + t2 + t3, "Must be t3 period.");
        _;
    }

    modifier t4_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4, "Must be t4 period.");
        _;
    }

    modifier t5_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5, "Must be t5 period.");
        _;
    }

    modifier t6_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6, "Must be t6 period.");
        _;
    }

    modifier t8_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8, "Must be t8 period.");
        _;
    }

    modifier t9_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 + t8 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9, "Must be t9 period.");
        _;
    }

    modifier t10_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 + t8 + t9 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + t10, "Must be t10 period.");
        _;
    }

    modifier t11_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 + t8 + t9 + t10 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + t10 + t11, "Must be t11 period.");
        _;
    }

    modifier t12_in_progress() {
        require(block.timestamp > session.start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 + t8 + t9 + t10 + t11 && block.timestamp <=session.start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + t10 + t11 + t12, "Must be t12 period.");
        _;
    }

    function hash(uint _x, uint _n) public pure returns(bytes32) {
        return keccak256(abi.encodePacked(_x, _n));
    }

    function register() public payable deposit_paid_register not_registered only_participants {
        participants[msg.sender] = Participant(true, n, msg.value, 0, 0, false, false, 0);
        n += 1;
    }

    function new_session() public payable only_dealer deposit_and_reward_paid_session no_active_session {
        session.active = true;
        session.reward = rho;
        session.start_time = block.timestamp;
        session.dealer_deposit = msg.value - rho; // >= d_prime
    }

    function withdraw() public registered {

        uint deposit_to_send = participants[msg.sender].deposit;

        if (participants[msg.sender].deposit_partly_frozen) {
            deposit_to_send = participants[msg.sender].deposit - d_star;
        }

        if (participants[msg.sender].deposit_frozen) {
            deposit_to_send = 0;
        }

        uint amount_to_send = deposit_to_send + dealer_cheating_rewards + session_rewards - participants[msg.sender].reward_withdrawn + participants[msg.sender].reward;
        
        // not correct actually :( participant may collect rewards for sessions he didn;t participate, how to avoid for loop???
        participants[msg.sender].reward_withdrawn += dealer_cheating_rewards + session_rewards; // this is done to avoid for loops in sending rewards 

        participants[msg.sender].deposit = 0;
        participants[msg.sender].registered = false;
        participants[msg.sender].commit = 0;
        participants[msg.sender].deposit_frozen = false;
        participants[msg.sender].deposit_partly_frozen = false;
        participants[msg.sender].reward = 0;
        // think about index?

        n -= 1;

        (bool sent, bytes memory data) = msg.sender.call{value: amount_to_send}("");
        require(sent, "failed to send ether");
    }

    function participate_again() public payable deposit_paid_register registered only_participants no_active_session{
        participants[msg.sender].deposit = msg.value;
        participants[msg.sender].deposit_frozen = false;

        n += 1;
    }


    // Step 1: Off-chain commitment

    // Step 2: On-chain Commitment Request
    function request_commit(address _addr) public only_dealer active_session t2_in_progress {
        participants[_addr].deposit_frozen = true;
    }

    // Step 3: On-chain Commitment
    function commit(bytes32 _c) public funds_frozen active_session t3_in_progress{
        participants[msg.sender].deposit_frozen = false;
        participants[msg.sender].commit = _c;
    }

    // Step 4: Merkle Tree Announcement
    function announce_commit_root(bytes32 _root_T_c) public only_dealer active_session t4_in_progress {
        session.root_T_c = _root_T_c;
    }

    // Step 5: On-chain Commitment Challenges
    function challenge_commitment(address _addr) public not_challenged(_addr) active_session t5_in_progress {
        participants[msg.sender].deposit_partly_frozen = true;
        challenged_participants[_addr] = true; // commitment of _addr is not correctly included
        challenging_participants[_addr] = msg.sender; // msg.sender challenged commitment of _addr
    }

    function verify_merkle_proof(bytes32[] memory _proof, bytes32 _root, bytes32 _leaf, uint _index) public pure returns (bool) {
        bytes32 hash = _leaf;

        for (uint i = 0; i < _proof.length; i++) {
            bytes32 proof_element = _proof[i];

            if (_index % 2 == 0) {
                hash = keccak256(abi.encodePacked(hash, proof_element));
            } else {
                hash = keccak256(abi.encodePacked(proof_element, hash));
            }
            _index /= 2;
        }
        return hash == _root;
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature); 

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function verify_signature(address _signer, bytes32 _messageHash, bytes memory signature) public pure returns (bool) {
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(_messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function verify_hash( uint _x, uint _n, address _addr) public view returns (bool) {
        return hash(_x, _n) == participants[_addr].commit;
    }

    // Step 6: On-chain Responses
    function commitment_challenge_response(address _addr, uint j, bytes32[] memory _proof, bytes32 _c, bytes memory _signature) public only_dealer active_session t6_in_progress{

        bool proof_verified = verify_merkle_proof(_proof, session.root_T_c, _c, j); // replaced participants[_addr].index with j, dealer should provide index
        // require(proof_verified, "Merkle proof was not verified.");

        bool signature_verified = verify_signature(_addr, _c, _signature);
        // require(signature_verified, "Signature was not verified.");

        // how to verify without a for loop that dealer provided response for all challenges??

        if (!proof_verified || !signature_verified) {
            // correct reward calculation later!!
            dealer_cheating_rewards += (session.dealer_deposit / n);
            session_rewards += (session.reward / n);

            session.dealer_deposit = 0;
            session.active = false;

            address challenging_participant = challenging_participants[_addr];
            participants[challenging_participant].deposit_partly_frozen = false;
        }
        
        // should implement mechanism for sending funds if checks above fail

        uint gas_usage = 1000; // just for test

        if (d_star > gas_usage/2) {
            dealer_funds += (gas_usage/2);
        }
        else {
            dealer_funds += d_star;
        }
    }

    // Step 7: Off-chain Revealing

    // Step 8: On-chain Revealing Request
    function request_reveal(address _addr) public only_dealer active_session t8_in_progress {
        participants[_addr].deposit_frozen = true;
        dealer_funds_partly_frozen = true;
    }

    // Step 9: On-chain Revealing
    function reveal(uint i, bytes32[] memory _proof, bytes32 _c, uint _x, uint _n) public funds_frozen active_session t9_in_progress{
        
        bool proof_verified = verify_merkle_proof(_proof, session.root_T_c, _c, i);
        bool hash_verified = verify_hash(_x, _n, msg.sender);

        if (proof_verified && hash_verified) {
            participants[msg.sender].deposit_frozen = false;
        }
        // also add if participant fails to reveal part

        uint gas_usage = 1000; // just for test
        if (d_star > gas_usage/2) {
            participants[msg.sender].reward += (gas_usage/2);
            session.dealer_deposit -= (gas_usage/2);
        }
        else {
            participants[msg.sender].reward += d_star;
            session.dealer_deposit -= d_star;
        }

        dealer_funds_partly_frozen  = false;
    }

    // Step 10: Final Merkle Tree Announcement
    function announce_root(bytes32 _root_T) public only_dealer active_session t10_in_progress {
        session.root_T = _root_T;
    }

    // Step 11: On-chain Challenges
    function challenge(address _addr) public not_challenged(_addr) active_session t11_in_progress {
        participants[msg.sender].deposit_partly_frozen = true;
        challenged_participants[_addr] = true;
        challenging_participants[_addr] = msg.sender;
    }

    // Step 12: On-chain Responses
    function challenge_response(address _addr, uint j, bytes32[] memory _proof_commit, bytes32 _c, bytes memory _signature, bytes32[] memory _proof_reveal, uint _x, uint _n) public only_dealer active_session t12_in_progress{

        bool proof_commit_verified = verify_merkle_proof(_proof_commit, session.root_T_c, _c, j);
        //require(proof_commit_verified, "Merkle proof was not verified.");

        // write another check proof for uint / not bytes32
        // bool proof_reveal_verified = verify_merkle_proof(_proof_reveal, root_T, _x, participants[_addr].index);
        // require(proof_reveal_verified, "Merkle proof was not verified.");

        bool signature_verified = verify_signature(_addr, _c, _signature);
        //require(signature_verified, "Signature was not verified.");

        bool hash_verified = verify_hash(_x, _n, _addr);
        //require(hash_verified, "Hash/commit was not verified.");
        if (!proof_commit_verified || !signature_verified || !hash_verified) {
            // do smth
            session.dealer_deposit = 0;
        }
    }

    // Step 13: Verifiable Delay Function

    // Step 14: VDF Challenge



   
}