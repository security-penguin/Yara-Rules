rule Atomic_Stealer_Hex {
    meta:
		version = "1.0"
        author = "security-penguin"
        description = "Detects Atomic Stealer targeting MacOS"
        date = "2024-04-014"
        reference1 = "https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp"
	    reference2 = "https://www.bleepingcomputer.com/news/security/macos-info-stealers-quickly-evolve-to-evade-xprotect-detection/"
	    reference3 = "https://github.com/RussianPanda95/Yara-Rules/blob/main/AtomicStealer/Atomic_Stealer.yar"
    	triage_description = "Atomic Stealer Hex."
        triage_score = 10		
		category = "MALWARE"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		malware_type = "INFOSTEALER"
		mitre_att = "T1204.002"
		actor_type = "CRIMEWARE"
		source = "security-penguin"
    strings:
		$hex1 = {36 66 37 33}
		$hex2 = {36 31 37 33}
    condition:	
        1 of ($hex*)

}