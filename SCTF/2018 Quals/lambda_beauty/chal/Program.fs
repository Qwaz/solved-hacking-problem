open Lambda.AST

let flag = "SCTF{##### READ ME IF YOU CAN ######}"

[<EntryPoint>]
let main argv =
  System.Console.Write ">>> "
  try
    let r = System.Console.ReadLine () |> Lambda.Util.parse
    let result = r <<< (Lambda.Church.ofString flag)
               |> Lambda.Eval.evalWithTimeout 5000
    match result with
    | Some (x) ->
        System.Console.WriteLine "The result seems to be Object!"
        System.Console.WriteLine "Good Job!"
    | None ->
        System.Console.WriteLine "Timeout!"
  with
    | _ -> System.Console.WriteLine "Illegal input"
  0
