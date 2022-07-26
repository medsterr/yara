rule generic_dirty_pickle_payload
{
    meta:
        version = "1.0"
        date = "2022-07-22"
        description = "Generic rule to identify weaponized pickles based on pickle injector POC."
        author = "Medicus Riddick (NVIDIA)/John Irwin (NVIDIA)"
        reference = "https://github.com/medsterr/yara/python/pickle_injector"
	reference = "https://github.com/coldwaterq/pickle_injector"
        Tactic = "Execution"
        Technique = "T1059:Command and Scripting Interpreter:Python"
        FPRate = "Low"

    strings:

        // Decompressed Exploit Payload Strings (Example)
        /*
            94250272: \x80                                             PROTO      2
            94250274: c                                                GLOBAL     '__builtin__ exec'
            94250292: (                                                MARK
            94250293: c                                                    GLOBAL     'zlib decompress'
            94250310: (                                                    MARK
            94250311: B                                                        BINBYTES   b'x\xda\xac...\x80\x12'
            94282393: t                                                        TUPLE      (MARK at 94250310)
            94282394: R                                                    REDUCE
            94282395: t                                                    TUPLE      (MARK at 94250292)
            94282396: R                                                REDUCE
            94282397: 0                                                POP
            94282398: \x80                                             PROTO      4
        */

        // Weaponized Pickle
        $weaponized_pickle = { 63 ( 62 75 69 6C 74 69 6E 73 | 5F 5F 62 75 69 6C 74 69 ( 6E | 6E 73 ) 5F 5F ) ?? ( 65 78 65 63 | 65 76 61 6C ) ?? 28 63 ( 7A 6C 69 62 | 62 61 73 65 36 34 ) ?? ( 64 65 63 6F 6D 70 72 65 73 73 | 62 36 34 64 65 63 6F 64 65 ) ?? 28 42 [-] ?? ( 74 52 74 52 30 | 74 52 28 74 52 ) }

    condition:
        $weaponized_pickle
}
