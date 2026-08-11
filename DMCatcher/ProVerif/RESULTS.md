# Archived ProVerif result audit

This directory contains three released model sources and their saved ProVerif
outputs. `formal-results.csv` is a literal reconciliation of the query
declarations and `RESULT` lines; it does not estimate or simulate checker
results.

The manuscript applies five checks before interpretation: A1, equation
consistency; A2, queried-term identity; A3, event-variable binding; A4,
identity/session/message binding; and A5, deployed-trust fidelity.

- Matrix: 12/12 correspondence results (2 true, 10 false) and 4/4 secrecy
  results (all true). Some correspondences contain consequent parameters absent
  from the antecedent, and two ciphertext queries address global private names
  shadowed by local process bindings (A2--A5 fail). The counts are artifact diagnostics, not
  an aggregate Matrix secrecy/authenticity verdict.
- Berty: 7/7 correspondence results (all false) and 2/2 secrecy results (both
  true). Identity/session/message binding fails (A3 and A4), while deployed
  trust fidelity cannot be established from the retained mapping (A5-U). These
  outcomes prevent an aggregate
  protocol interpretation.
- Status: 3 reported correspondence results for 4 declarations (all three
  false) and 2/2 secrecy results (both true). The model uses the wrong responder
  Diffie--Hellman term and omits deployed contact verification (A1 and A5), so
  this output is excluded from protocol conclusions.

The archive does not identify the original ProVerif executable version,
command line, or runtime. A literal `RESULT` line is promoted to a security
claim only after its source and query pass the admissibility checks described in
the manuscript. None of these sources models timed compromise, erasure,
recovery, PFS, or PCS.
