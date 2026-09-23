rule GODSEYE_EICAR_Antivirus_Test_File
{
  meta: description = "Detects the harmless EICAR antivirus test string"
  strings: $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition: $eicar
}
