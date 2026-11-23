# Contributing to Xray-core

We review pull requests that address a concrete problem or an agreed proposal. Please keep each change focused and provide evidence that maintainers can check.

## Bug fixes

A bug-fix pull request must link an existing issue filed using the issue template. Summarize the code change and verification in the pull request, and add a regression test when practical. A speculative fix without a demonstrated problem is not ready for a pull request.

## Features

Propose the use case and intended design in an issue before implementing it. Wait for a maintainer to accept the proposal. Explain how the change fits the existing architecture and any compatibility impact.

## Refactors

Propose the scope in an issue and wait for maintainer acceptance before implementing it. Show which complexity the change removes and why the resulting design is easier to understand. Prefer a reduction in code and moving parts, but line count alone is not the review criterion. Preserve observable behavior and test both old-to-new and new-to-old client/server connections when protocol or network behavior is affected.

## AI involvement and author responsibility

AI assistance does not require a conversation record when the author selects or verifies the problem, directs the approach, reviews every changed line, verifies the result, and personally responds to review feedback. The author must be able to explain every changed line and maintain the change. A pull request meeting these conditions is considered human-led, regardless of whether AI wrote the code or who pushed the commits. Such pull requests may ignore the agent-led requirements below.

If an AI agent independently selected the task or made key implementation decisions without ongoing human direction, the pull request is agent-led even if a person submits it manually. Disclose each tool and model and paste the complete prompt-and-response record for every session used for the pull request, including retries and changes after review feedback, inside a collapsed `<details>` block in the pull request description. External links, summaries, and selected excerpts are insufficient. A transcript does not replace the author's review, verification, or responsibility for responding to maintainers.

In agent-led pull requests, commits containing AI-generated changes must credit the specific LLM as their author or co-author.

We do not oppose the use of AI, but agent-led pull requests must have a human author who responds to maintainer feedback for several weeks after submission. Dishonest declarations, fabricated verification, intentionally incomplete records, or abandoning an agent-led pull request are prohibited and may result in being blocked from contributing to Xray-core.

## Review

Maintainers may ask for missing evidence before reviewing code or close a pull request that is outside the agreed scope. The contributor is responsible for understanding, testing, and explaining the change, regardless of the tools used to produce it.
