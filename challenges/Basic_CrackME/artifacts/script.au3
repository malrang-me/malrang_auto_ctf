Func _CALC ( $DATA , $WPARAM = + 4294967295 )
	Local $OPCODE = "0xC800040053BA2083B8EDB9000100008D41FF516A0859D1E8730231D0E2F85989848DFCFBFFFFE2E78B5D088B4D0C8B451085DB7416E3148A1330C20FB6D2C1E80833849500FCFFFF43E2ECF7D05BC9C21000"
	Local $CODEBUFFER = DllStructCreate ( "byte[" & BinaryLen ( $OPCODE ) & "]" )
	DllStructSetData ( $CODEBUFFER , 1 , $OPCODE )
	Local $INPUT = DllStructCreate ( "byte[" & BinaryLen ( $DATA ) & "]" )
	DllStructSetData ( $INPUT , 1 , $DATA )
	Local $RET = DllCall ( "user32.dll" , "uint" , "CallWindowProc" , "ptr" , DllStructGetPtr ( $CODEBUFFER ) , "ptr" , DllStructGetPtr ( $INPUT ) , "int" , BinaryLen ( $DATA ) , "uint" , $WPARAM , "int" , 0 )
	$INPUT = 0
	$CODEBUFFER = 0
	Return $RET [ 0 ]
EndFunc
Func GETUSERINPUT ( )
	Local $INPUT = InputBox ( "Basic CrackME" , "값을 입력하세요:" , "" , "" , + 4294967295 , + 4294967295 , 0 , 0 )
	Return $INPUT
EndFunc
Func VALIDATEINPUT ( $INPUT )
	If StringLen ( $INPUT ) <> 32 Then
		Return False
	EndIf
	Local $FLAG [ 33 ] = [ 0 , 2746444411 , 2852464208 , 366298950 , 3110714886 , 1812594658 , 252678971 , 1993550751 , 3865851406 , 2238339799 , 4024072741 , 1657960400 , 701932439 , 2564639411 , 4024072741 , 453955444 , 701932439 , 3904355900 , 2013832109 , 3904355900 , 2517025409 , 4225443434 , 453955444 , 4024072741 , 453955444 , 701932439 , 3554254580 , 3372436105 , 3187964447 , 878818291 , 3707901638 , 3187964447 , 4239843955 ]
	Local $INPUT_FLAG [ 33 ]
	$INPUT_FLAG [ 0 ] = 0
	Local $I
	For $I = 1 To StringLen ( $INPUT )
		$CHAR = StringMid ( $INPUT , $I , 1 )
		$CALC = _CALC ( $CHAR )
		$CHECK = BitXOR ( 3735929054 , Number ( $CALC ) )
		If $FLAG [ $I ] <> $CHECK Then
			Return False
		EndIf
	Next
	Return True
EndFunc
Local $INPUT = GETUSERINPUT ( )
If VALIDATEINPUT ( $INPUT ) Then
	MsgBox ( 0 , "Result" , "Correct" )
EndIf
