//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;
import { VerifyVDF } from "./VerifyVDF.sol";

contract gasRNG {
    // for now it's hardcoded for easy testing, then we should create a constructor
    address public dealer;
    uint public constant d = 1 ether; // register deposit
    uint public constant d_star = 0.5 ether; // challenging commitment
    uint public constant d_prime = 0.5 ether; // session deposit by dealer

    uint public dealer_funds = 0; 
    bool public dealer_funds_partly_frozen; 
    bool public dealer_deposit_frozen; 
    bool public dealer_responded_to_challenge; 

    uint public constant t1 = 2 minutes;
    uint public constant t2 = 2 minutes;
    uint public constant t3 = 2 minutes;
    uint public constant t4 = 2 minutes;
    uint public constant t5 = 2 minutes;
    uint public constant t6 = 2 minutes;
    uint public constant t7 = 2 minutes;
    uint public constant t8 = 2 minutes;

    uint public rho = 1 ether; // session reward

    // bytes32 public root_T_c; // root of the merkle tree commit
    // bytes32 public root_T; // root of the merkle tree final

    uint public n = 0; // number of participants

    VerifyVDF public verify_vdf;

    constructor(address verify_vdf_address) {
        dealer = msg.sender;
        verify_vdf = VerifyVDF(verify_vdf_address);
    }

    struct Participant {
        bool registered;
        uint index;
        uint deposit;
        uint reward_withdrawn;
        uint submit;
        bool deposit_frozen;
        bool deposit_partly_frozen;
        uint reward;
        bool requested_submit;
    }

    mapping(address => Participant) public participants;

    mapping(address => bool) public challenged_participants;
    mapping(address => address) public challenging_participants;

    struct Session {
        bool active;
        uint reward;
        uint start_time;
        uint dealer_deposit;
        bytes32 root_T; // root of the merkle tree final
        uint no_of_participants;
        uint dealer_cheating_rewards;
    }

    mapping(uint => Session) public sessions;

    // sessions.
    uint session_id = 0;
    // Session public session = Session(false, 0, 0, 0, 0);


    // uint public dealer_cheating_rewards = 0; 
    uint public session_rewards = 0; 

    struct Result {
        bytes g;
        bytes pi;
        bytes y;
        bytes q;
        bytes dst;
        uint256 nonce;
        uint256 delay;
    }
    Result public dealer_result = Result("", "", "", "", "", 0, 0);

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
        require(!sessions[session_id].active, "There is an active session.");
        _;
    }

    modifier active_session() {
        require(sessions[session_id].active, "There is no active session in progress.");
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

    modifier requested_submit(address _addr) {
        require(participants[_addr].requested_submit, "Participant submitted value successfully.");
        _;
    }

    modifier not_challenged(address _addr) {
        require(!challenged_participants[_addr], "Participant is already challenged.");
        _;
    }


    modifier t2_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 && block.timestamp <=sessions[session_id].start_time + t1 + t2, "Must be t2 period.");
        _;
    }

    modifier t3_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 && block.timestamp <=sessions[session_id].start_time + t1 + t2 + t3, "Must be t3 period.");
        _;
    }

    modifier after_t3() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3, "We can check if participant did not submit the value only after t3 period.");
        _;
    }

    modifier t4_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 && block.timestamp <=sessions[session_id].start_time + t1 + t2 + t3 + t4, "Must be t4 period.");
        _;
    }

    modifier t5_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 + t4 && block.timestamp <=sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5, "Must be t5 period.");
        _;
    }

    modifier t6_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 && block.timestamp <=sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 + t6, "Must be t6 period.");
        _;
    }

    modifier after_t6() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 + t6, "We can check if dealer did not respond to all challenges only after t6 period.");
        _;
    }

    modifier t8_in_progress() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 && block.timestamp <=sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8, "Must be t8 period.");
        _;
    }

    modifier after_t8() {
        require(block.timestamp > sessions[session_id].start_time + t1 + t2 + t3 + t4 + t5 +t6 + t7 + t8, "Dealer can end the session only after t8.");
        _;
    }

    function hash(uint _x, uint _n) public pure returns(bytes32) {
        return keccak256(abi.encodePacked(_x, _n));
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

    // function verify_hash( uint _x, uint _n, address _addr) public view returns (bool) {
    //     return hash(_x, _n) == participants[_addr].submit;
    // }


    function register() public payable deposit_paid_register not_registered only_participants {
        participants[msg.sender] = Participant(true, n, msg.value, 0, 0, false, false, 0, false);
        n += 1;
    }

    function new_session() public payable only_dealer deposit_and_reward_paid_session no_active_session {

        sessions[session_id] = Session(false, 0, 0, 0, 0, 0, 0);

        sessions[session_id].active = true;
        sessions[session_id].reward = rho;
        sessions[session_id].start_time = block.timestamp;
        sessions[session_id].dealer_deposit = msg.value - rho; // >= d_prime
        sessions[session_id].no_of_participants = n;
        session_id += 1;
    }

    function withdraw() public registered no_active_session {

        uint deposit_to_send = participants[msg.sender].deposit;

        if (participants[msg.sender].deposit_partly_frozen) {
            deposit_to_send = participants[msg.sender].deposit - d_star;
        }

        if (participants[msg.sender].deposit_frozen) {
            deposit_to_send = 0;
        }
        // have a loop here through participants[msg.sender][session_id].rewards
        // uint amount_to_send = deposit_to_send + dealer_cheating_rewards + session_rewards - participants[msg.sender].reward_withdrawn + participants[msg.sender].reward;
        
        // not correct actually :( participant may collect rewards for sessions he didn;t participate, how to avoid for loop???
        // participants[msg.sender].reward_withdrawn += dealer_cheating_rewards + session_rewards; // this is done to avoid for loops in sending rewards 

        // sessions[session_id].dealer_cheating_rewards loop 
        participants[msg.sender].deposit = 0;
        participants[msg.sender].registered = false;
        participants[msg.sender].submit = 0;
        participants[msg.sender].deposit_frozen = false;
        participants[msg.sender].deposit_partly_frozen = false;
        participants[msg.sender].reward = 0;
        // think about index?

        n -= 1;

        // (bool sent, bytes memory data) = msg.sender.call{value: amount_to_send}("");
        // require(sent, "failed to send ether");
    }

    function participate_again() public payable deposit_paid_register registered only_participants no_active_session{
        participants[msg.sender].deposit = msg.value;
        participants[msg.sender].deposit_frozen = false;

        n += 1;
    }


    // Step 1: Off-chain Submitting

    // Step 2: On-chain Submitting Request
    function request_submit(address _addr) public only_dealer active_session t2_in_progress {
        participants[_addr].deposit_frozen = true;
        participants[_addr].requested_submit = true;
        dealer_funds_partly_frozen = true;
    }

    // Step 3: On-chain Submitting //  funds_frozen active_session t3_in_progress
    function submit(uint _x) public {
        uint gas_before = gasleft();

        participants[msg.sender].deposit_frozen = false;
        participants[msg.sender].submit = _x;
        participants[msg.sender].requested_submit = false;

        uint gas_after = gasleft();

        uint gas_next_constant = 80000; // we require more gas for the next operations, so we set is as an overhead constant
        uint gas_usage = gas_before - gas_after + gas_next_constant; 

        if (d_star > gas_usage/2) {
            participants[msg.sender].reward += (gas_usage/2);
            sessions[session_id].dealer_deposit -= (gas_usage/2);
        }
        else {
            participants[msg.sender].reward += d_star;
            sessions[session_id].dealer_deposit -= d_star;
        }
    }

    // call this function when participant did not submit by the deadline
    function did_not_submit(address _addr) public requested_submit(_addr) active_session after_t3 {
        dealer_funds_partly_frozen = false;
        participants[_addr].submit = 0;
    }

    // Step 4: Merkle Tree Announcement
    function announce_root(bytes32 _root_T) public only_dealer active_session t4_in_progress {
        sessions[session_id].root_T = _root_T;
    }

    // Step 5: On-chain Challenges
    function challenge(address _addr) public not_challenged(_addr) active_session t5_in_progress {
        participants[msg.sender].deposit_partly_frozen = true;
        challenged_participants[_addr] = true; // commitment of _addr is not correctly included
        challenging_participants[_addr] = msg.sender; // msg.sender challenged commitment of _addr
    }

    // Step 6: On-chain Responses
    function challenge_response(address _addr, bytes32[] memory _proof, bytes32 _x, bytes memory _signature) public only_dealer active_session t6_in_progress{

        uint gas_before = gasleft();

        bool proof_verified = verify_merkle_proof(_proof, sessions[session_id].root_T, _x, participants[_addr].index);
        bool signature_verified = verify_signature(_addr, _x, _signature);

        if (!proof_verified || !signature_verified) {
            // correct reward calculation later!!
            sessions[session_id].dealer_cheating_rewards += (sessions[session_id].dealer_deposit / sessions[session_id].no_of_participants);
            sessions[session_id].reward += (sessions[session_id].reward /  sessions[session_id].no_of_participants);

            sessions[session_id].dealer_deposit = 0;
            sessions[session_id].active = false;

            address challenging_participant = challenging_participants[_addr];
            participants[challenging_participant].deposit_partly_frozen = false;
        }
        else {
            uint gas_after = gasleft();

            uint gas_next_constant = 80000; // we require more gas for the next operations, so we set is as an overhead constant
            uint gas_usage = gas_before - gas_after + gas_next_constant; 

            if (d_star > gas_usage/2) {
                dealer_funds += (gas_usage/2);
            }
            else {
                dealer_funds += d_star;
            }
        }

        // it indicates that the dealer responded to challenge (even if he couldn't prove it, his deposit was confiscated already)
        challenged_participants[_addr] = false;
        
        
    }

    // this function is for participants to claim that the dealer did not respond to all challenges on time
    function did_not_respond_to_challenge(address _addr) public after_t6 {
        require(!challenged_participants[_addr], "Dealer already responded to the challenge for this participant.");
        require(!dealer_responded_to_challenge, "This function can be called only once");

        sessions[session_id].dealer_cheating_rewards += (sessions[session_id].dealer_deposit / sessions[session_id].no_of_participants);
        sessions[session_id].reward += (sessions[session_id].reward /  sessions[session_id].no_of_participants);

        sessions[session_id].dealer_deposit = 0;
        sessions[session_id].active = false;

        address challenging_participant = challenging_participants[_addr];
        participants[challenging_participant].deposit_partly_frozen = false;
        challenged_participants[_addr] = false;
    }



    // Step 7: Verifiable Delay Function
    function announce_result(bytes memory g, bytes memory pi, bytes memory y, bytes memory q, bytes memory dst, uint256 nonce, uint256 delay) external {
        dealer_result.g = g;
        dealer_result.pi = pi;
        dealer_result.y = y;
        dealer_result.q = q;
        dealer_result.dst = dst;
        dealer_result.nonce = nonce;
        dealer_result.delay = delay;
    }

    // Step 8: VDF Challenge

    function challenge_result(bytes memory g, bytes memory pi, bytes memory y, bytes memory q, bytes memory dst, uint256 nonce, uint256 delay) external returns (bool) {
        bool res_participant_correct = verify_vdf.verify(g, pi, y, q, dst, nonce, delay);
        bool res_dealer_correct = verify_vdf.verify(dealer_result.g, dealer_result.pi, dealer_result.y, dealer_result.q, dealer_result.dst, dealer_result.nonce, dealer_result.delay);
    
        if (res_participant_correct && !res_dealer_correct) {
            dealer_deposit_frozen = true;
            // then increase participant reward
        }
    }

    function end_session() public after_t8 only_dealer active_session {
        sessions[session_id].active = false;
        sessions[session_id].no_of_participants = n;
    }

   
}