rule Atomic_Stealer_B {
    meta:
        version = "1.0"
        author = "security-penguin"
        description = "Detects Atomic Stealer targeting MacOS"
        date = "2024-04-014"
        reference1 = "https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp"
	    reference2 = "https://www.bleepingcomputer.com/news/security/macos-info-stealers-quickly-evolve-to-evade-xprotect-detection/"
	    reference3 = "https://github.com/RussianPanda95/Yara-Rules/blob/main/AtomicStealer/Atomic_Stealer.yar"
        triage_description = "Atomic Stealer, variant B."
        triage_score = 10
		category = "MALWARE"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		malware_type = "INFOSTEALER"
		mitre_att = "T1204.002"
		actor_type = "CRIMEWARE"
		source = "security-penguin"
    strings:
        $s1 = "osascript -e '"
		$s2 = "12supermegahuxPKc"
		$s3 = "UUUW"
    condition:	
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of ($s*)

}