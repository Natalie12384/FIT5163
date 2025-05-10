# FIT5163
Requirements:
    Secure voting system. 
    Develop a secure online voting system that ensures the integrity, confidentiality, and verifiability of votes. 

    a. Implement a secure voting protocol that uses cryptographic techniques to ensure vote confidentiality and integrity. 

    b. Develop a user interface for voter registration, voting, and result viewing. 

    c. Ensure voter authentication and authorization, preventing double voting and unauthorised access. 

    d. Implement a mechanism for voters to verify that their vote was counted without revealing their choice. (optional, will give 2 bonus marks) 

    e. Use blockchain technology to provide an immutable audit trail of votes (optional, will give 2 bonus marks). 

Parties in e-voting protocol:
- Registration authority
- voter
- Election authority/ies - signer
- Tallying authority/ies - verifier

Threat Model:
    Protect:
    - voter identity 
    - vote (confidentiality)
    - vote integrity
    - vote anonymity
    - election results
    Attackers:
    - double voters
    - eavesdroppers (those that observe the data in the communication channel)
    - content manipulators (aim to change vote and generate valid sig from it)
    - internal manipulators 

We assume:
- visible communication channel, some areas are visible

Try:
- blind sig for basic single signing/verifier
- ask how to determine if multiple signers is needed, and how to go about showing this code wise or functionally wise 
- encryption of vote (confidentiality)
- password/username (authentication)
- commitment scheme

Protocol steps:
└── registered_voters.json      # Directory of registered voter public keys


INSTRUCTIONS 
Use 'npm install' to get all dependencies
In terminal, execute the app.py file and from the terminal either press the link or type in 'http://localhost:8000'

