\# ScamShield — AI Scam Detection System (Malaysia)



\## Overview



ScamShield is a lightweight fraud detection system designed to help Malaysians identify potential scams in messages and phone numbers. The system combines rule-based analysis with Google Gemini to provide fast and explainable risk assessments.



\---



\## Problem



Scams in Malaysia are increasing rapidly, especially through:



\* Banking phishing messages

\* Government impersonation (PDRM, LHDN)

\* Parcel delivery scams

\* Fake job and investment offers



Most users cannot quickly determine whether a message is safe, which leads to financial losses.



\---



\## Solution



ScamShield provides a simple interface to:



\* Analyse suspicious messages

\* Check phone number risk

\* View recent scam-related news



The goal is to give users a \*\*quick and understandable risk assessment\*\* before they take action.



\---



\## System Design



The system does not rely on AI alone. It uses a two-stage workflow:



\### 1. Rule-Based Analysis



The backend first scans the input for:



\* Links

\* Urgency keywords (e.g. “urgent”, “final warning”)

\* Authority references (e.g. PDRM, LHDN)

\* Payment-related terms



It also checks the message against known scam patterns.



\### 2. AI Analysis (Gemini)



The extracted signals are passed into Gemini, which:



\* Interprets the message in context

\* Classifies risk level

\* Provides explanation and advice



\### 3. Final Decision



The system combines rule-based signals with AI output to produce a final risk score and explanation.



\---



\## Features



\* Message scam analysis (SMS, WhatsApp, email)

\* Phone number risk detection

\* Malaysia-specific scam pattern recognition

\* Live scam news feed

\* Structured, readable results



\---



\## Technology Stack



\* Frontend: HTML, CSS, JavaScript

\* Backend: FastAPI (Python)

\* AI Model: Google Gemini (Flash Latest)

\* External Data: Google News RSS



\---



\## Security



\* API keys stored in environment variables

\* Input validation on all endpoints

\* Controlled JSON parsing for AI responses



\---



\## How to Run



Install dependencies:



```bash



pip install -r requirements.txt



```



Start backend:



```bash



python -m uvicorn main:app --reload --port 8000



```



Open the frontend by launching `index.html`.



\---



\## Impact



ScamShield helps users make safer decisions by:



\* Highlighting suspicious patterns early

\* Providing clear explanations instead of raw AI output

\* Increasing awareness of common scam techniques



\---



\## Hackathon Track



Track 5 — Secure Digital (FinTech \& Security)



\---



\## Notes



This project uses AI as a supporting tool rather than the only decision-maker.

Rule-based checks are used to improve reliability and reduce false outputs.

