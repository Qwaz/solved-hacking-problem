' Keygen Me.FRM
Option Explicit
Declare Function extfn0103 Lib "Kernel" Alias "GetVersion" () As Long ' 2
Dim m001C(256, 6) As Long ' 72
Dim m0036(6) As Long ' 72

Sub sub0074 ()
Dim l004C As String ' 87
Dim l004E As Integer ' 81
Dim l0050 ' 80
Dim l0052 As Long ' 82
    l004C = App.Path
    If  Right(l004C, 1) <> "\" Then
        l004C = l004C + "\"
    End If
    l004C = l004C + App.EXEName + ".exe"
    Open l004C For Binary Access Read As #1
    l0052 = LOF(1)
    While l0052 <> 0
        Get #1, , l0050
        l004E = l004E Xor l0050
        l0052 = l0052 - 2
    Wend
    Close #1
    If  l004E <> 0 Then
        MsgBox "File was modified"
        End
    End If
End Sub

Sub cont6_Click ()
    End
End Sub

Sub cont5_Click ()
Dim l0058() As Long ' 92
Dim l005E As String ' 87
Dim l0060 As String ' 87
Dim l0062 ' 80
Dim l0064() As Integer ' 91
    ReDim l0058(6) As Long
    l005E = "Nautilus Institute"
    sub00B4
    Call sub00D5(l0058())
    For l0062 = 1 To Len(l005E)
        Call sub00F6(l0058(), Asc(Mid(l005E, l0062, 1)))
    Next
    For l0062 = 1 To Len(cont3.Text)
        Call sub00F6(l0058(), Asc(Mid(cont3.Text, l0062, 1)))
    Next
    Call sub00C8(cont4.Text, l0064())
    For l0062 = UBound(l0064) To 1 Step -1
        Call sub00F6(l0058(), l0064(l0062))
    Next
    l0060 = ""
    For l0062 = 1 To 6
        l0060 = l0060 + Chr((l0058(l0062) \ (2 ^ 16)) And ((2 ^ 8) - 1))
        l0060 = l0060 + Chr((l0058(l0062) \ (2 ^ 8)) And ((2 ^ 8) - 1))
        l0060 = l0060 + Chr((l0058(l0062) \ (2 ^ 0)) And ((2 ^ 8) - 1))
    Next
    If  StrComp(l005E, l0060, 0) = 0 Then
        MsgBox "Serial is valid"
    End If
End Sub

Sub Form_Load ()
Dim l0076 As Integer ' 81
    If  (extfn0103() And ((2 ^ 8) - 1)) <> 3 Then
        l0076 = 1
    Else
        If  ((extfn0103() \ (2 ^ 8)) And ((2 ^ 8) - 1)) > 11 Then
            l0076 = 1
        End If
    End If
    If  l0076 Then
        MsgBox "Unrecognized windows version"
        End
    End If
    sub0074
    Me.Left = (Screen.Width - Me.Width) / 2
    Me.Top = (Screen.Height - Me.Height) / 2
    m0036(1) = &HBFA28E&
    m0036(2) = &HA408CB&
    m0036(3) = &H865C28&
    m0036(4) = 36685&
    m0036(5) = &H786B04&
    m0036(6) = &HA67791&
End Sub

Sub sub00B4 ()
Dim l007C ' 80
Dim l007E ' 80
Dim l0080 ' 80
Dim l0082() As Long ' 92
Dim l0088 ' 80
Dim l008C() As Long ' 92
    ReDim l0082(6)       As Long
    ReDim l008C(6) As Long
    For l007C = 1 To 6
        For l0080 = 0 To 23
            l0082(l007C) = (l0082(l007C) * 2) + (((m0036(7 - l007C) And (2 ^ l0080)) <> 0) And 1)
        Next
    Next
    For l007C = 0 To 255
        For l007E = 1 To 5
            l008C(l007E) = 0
        Next
        l008C(6) = l007C
        For l0088 = 1 To 8
            l0080 = l008C(6) And 1
            For l007E = 6 To 2 Step -1
                l008C(l007E) = (l008C(l007E) \ 2) + ((l008C(l007E - 1) And 1) * (2 ^ 23))
            Next
            l008C(1) = l008C(1) \ 2
            If  l0080 Then
                For l007E = 1 To 6
                    l008C(l007E) = l008C(l007E) Xor l0082(l007E)
                Next
            End If
        Next
        For l007E = 1 To 6
            m001C(l007C + 1, l007E) = l008C(l007E)
        Next
    Next
End Sub


Sub sub00C8 (ByVal p0092 ' 40, p0094() As Integer ' 51)
Dim l009A As Long ' 82
Dim l009C ' 80
Dim l009E As Integer ' 81
    Do While Len(p0092) Mod 4 <> 0
        p0092 = p0092 + "!"
    Loop
    For l009C = Len(p0092) To 1 Step -4
        l009A = (Asc(Mid(p0092, l009C, 1)) - 33)
        l009A = (l009A * 94) + (Asc(Mid(p0092, l009C - 1, 1)) - 33)
        l009A = (l009A * 94) + (Asc(Mid(p0092, l009C - 2, 1)) - 33)
        l009A = (l009A * 94) + (Asc(Mid(p0092, l009C - 3, 1)) - 33)
        ReDim Preserve p0094(l009E + 3)
        p0094(l009E + 1) = l009A And ((2 ^ 8) - 1)
        l009A = l009A \ (2 ^ 8)
        p0094(l009E + 2) = l009A And ((2 ^ 8) - 1)
        l009A = l009A \ (2 ^ 8)
        p0094(l009E + 3) = l009A And ((2 ^ 8) - 1)
        l009E = l009E + 3
    Next
End Sub

Sub sub00D5 (p00A0() As Long ' 52)
Dim l00A6 ' 80
    For l00A6 = 1 To 6
        p00A0(l00A6) = m0036(l00A6)
    Next
End Sub


Sub sub00E0 (p00A8() As Long ' 52)
Dim l00AE ' 80
    For l00AE = 1 To 6
        p00A8(l00AE) = p00A8(l00AE) Xor ((2 ^ 24) - 1)
    Next
End Sub

Sub sub00EA (p00B0 ' 40, p00B2() As Long ' 52)
Dim l00B8 As String ' 87
Dim l00BA ' 80
Dim l00BC As String ' 87
    For l00BA = 1 To 6
        l00BC = "000000" + Hex(p00B2(l00BA))
        l00BC = Right(l00BC, 6)
        l00B8 = l00B8 + l00BC + " "
    Next
    MsgBox (p00B0 + l00B8)
End Sub

Sub sub00F6 (p00BE() As Long ' 52, ByVal pv00C4 As Integer ' 81)
Dim l00C6 ' 80
    Call sub00E0(p00BE())
    pv00C4 = (pv00C4 Xor (p00BE(6) And ((2 ^ 8) - 1))) + 1
    For l00C6 = 6 To 2 Step -1
        p00BE(l00C6) = p00BE(l00C6) \ (2 ^ 8)
        p00BE(l00C6) = p00BE(l00C6) + ((p00BE(l00C6 - 1) And ((2 ^ 8) - 1)) * (2 ^ 16))
    Next
    p00BE(1) = p00BE(1) \ (2 ^ 8)
    For l00C6 = 1 To 6
        p00BE(l00C6) = p00BE(l00C6) Xor m001C(pv00C4, l00C6)
    Next
    Call sub00E0(p00BE())
End Sub

