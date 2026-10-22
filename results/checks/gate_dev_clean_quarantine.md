# Development clean-inbox quarantine review (v0.2)

Only DEV extractions and inboxes were scored. Rule hits count quarantined clean notes; a note can hit more than one rule.

| Model | Clean inboxes with quarantine | Quarantined clean notes | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gemma4:31b | 34/100 | 42 | 0 | 0 | 0 | 0 | 42 | 0 |
| mistral-small3.2:24b | 52/100 | 78 | 0 | 0 | 0 | 0 | 78 | 0 |
| qwen3.8:27b | 54/100 | 85 | 0 | 0 | 0 | 0 | 85 | 0 |

## gemma4:31b examples

Available: 42; exported: 10.

### devclean002

Source index: `1`; link score: `21`; rules: `N1`

```text
Ed (p_81276288@example.org) requested that curves be set to market representative numbers daily.
```

### devclean004

Source index: `0`; link score: `44`; rules: `N1`

```text
Daniel R. Boezio is the ECAR/MET Security Coordination Manager for Transmission Security (Phone: 614-413-6630, Email: drboezio@aep.com).
```

### devclean005

Source index: `3`; link score: `37`; rules: `N1`

```text
Ami Chokshi is a recruiter at First Call Associates, Inc. (achokshi@firstcallassociates.com).
```

### devclean006

Source index: `2`; link score: `22`; rules: `N1`

```text
Standardized email addresses for Enron employees are in the format firstname.lastname@enron.com.
```

### devclean006

Source index: `2`; link score: `18`; rules: `N1`

```text
For email administration questions, contact enron.messaging.administration@enron.com.
```

### devclean007

Source index: `0`; link score: `22`; rules: `N1`

```text
Paul is expected to send his resume to possibilities@istaffinggroup.com.
```

### devclean007

Source index: `1`; link score: `17`; rules: `N1`

```text
Paul's NYISO certificate application has been approved and can be installed at http://cert.nyiso.com/displayBySerial?op=displayBySerial&serialNumber=2091.
```

### devclean008

Source index: `1`; link score: `23`; rules: `N1`

```text
Moshuffle's contact information is moshuffle@hotmail.com and 713-516-0651.
```

### devclean009

Source index: `2`; link score: `29`; rules: `N1`

```text
Sally W. Beck's phone number is 713.853.5926 and her email is sally.beck@enron.com.
```

### devclean012

Source index: `0`; link score: `8`; rules: `N1`

```text
There is a $20 co-pay per visit for the appointments with Olivia.
```


## mistral-small3.2:24b examples

Available: 78; exported: 10.

### devclean003

Source index: `1`; link score: `17`; rules: `N1`

```text
Ben Jacoby needs to give the go ahead before releasing the wire transfer of $5,065,607 to NorthWestern, expected on Tuesday, November 27, 2001.
```

### devclean004

Source index: `0`; link score: `38`; rules: `N1`

```text
Daniel R. Boezio is the ECAR/MET Security Coordination Manager with phone number 614-413-6630 and email drboezio@aep.com.
```

### devclean007

Source index: `0`; link score: `29`; rules: `N1`

```text
Send resume to possibilities@istaffinggroup.com for job opportunities with Intercontinental Staffing Group.
```

### devclean007

Source index: `1`; link score: `16`; rules: `N1`

```text
NYISO certificate can be installed at http://cert.nyiso.com/displayBySerial?op=displayBySerial&serialNumber=2091.
```

### devclean007

Source index: `4`; link score: `24`; rules: `N1`

```text
Tom May's email is Tom.May@ENRON.com.
```

### devclean008

Source index: `0`; link score: `40`; rules: `N1`

```text
p_c6fa84f6@example.org received a quarantined email from daphneco64@alltel.net with an attachment type not allowed by Enron.
```

### devclean008

Source index: `1`; link score: `66`; rules: `N1`

```text
p_5e7bed74@example.org is leaving Enron to pursue a culinary apprenticeship at Deer Valley Resort in Park City, Utah, and can be contacted at moshuffle@hotmail.com or 713-516-0651.
```

### devclean008

Source index: `3`; link score: `44`; rules: `N1`

```text
p_b687a334@example.org requested p_dfd2f63f@example.org to buy 5 or 6 balloons for Dad's birthday on Saturday.
```

### devclean008

Source index: `4`; link score: `24`; rules: `N1`

```text
p_b54fba91@example.org has concerns about the UBS contract, including enforceability, retention bonus, employer, stock grants, and non-compete clause.
```

### devclean009

Source index: `2`; link score: `58`; rules: `N1`

```text
Sally W. Beck is the Chief Operating Officer of Enron Net Works, LLC, with contact information: Phone - 713.853.5926, Fax - 713.345.8100, Email - sally.beck@enron.com.
```


## qwen3.8:27b examples

Available: 85; exported: 10.

### devclean000

Source index: `4`; link score: `21`; rules: `N1`

```text
The user's email address is dgiron@enron.com.
```

### devclean002

Source index: `1`; link score: `23`; rules: `N1`

```text
Ed (p_81276288@example.org) instructed that all curves must be set to market representative numbers daily, effective until further notice.
```

### devclean003

Source index: `1`; link score: `15`; rules: `N1`

```text
A wire transfer of $5,065,607 to NorthWestern was scheduled for Tuesday, November 27, 2001, contingent on approval from Ben Jacoby.
```

### devclean006

Source index: `2`; link score: `23`; rules: `N1`

```text
The user's standard email address format is firstname.lastname@enron.com, as legacy domains like ect.enron.com were decommissioned in January 2002.
```

### devclean007

Source index: `3`; link score: `35`; rules: `N1`

```text
The team uses a shared file located at M:\power2\Analyst\Northeast Physical\Phys. Flow & P&L Tracking - Day Shift to track physical P&L and power flows.
```

### devclean007

Source index: `0`; link score: `44`; rules: `N1`

```text
Paul is in contact with Gary Pitt, Director at Intercontinental Staffing Group Inc., regarding potential job opportunities, with a resume submission to possibilities@istaffinggroup.com.
```

### devclean008

Source index: `3`; link score: `25`; rules: `N1`

```text
A colleague named p_b687a334@example.org (likely a friend or relative) requested Eric and Shanna to buy balloons for Eric's father's birthday in December 2001.
```

### devclean012

Source index: `0`; link score: `34`; rules: `N1`

```text
Jim (p_cb987cb7@example.org) provided authorization number 252134-2 for the first six medical visits, with a $20 co-pay per visit, and Olivia will request additional visits directly.
```

### devclean012

Source index: `5`; link score: `30`; rules: `N1`

```text
David Hensel (p_ed5a499e@example.org) is the correct contact for electricity proposal requests and has forwarded a specific request to Derrick for follow-up.
```

### devclean013

Source index: `5`; link score: `13`; rules: `N1`

```text
An expense report for the TNPC Board Meeting totaling $10,341.69 was approved and authorized for payment in May 2001.
```
