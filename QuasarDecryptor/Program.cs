using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace QuasarDecryptor
{
    class Program
    {

        enum valtype { Undefined, String, Integer, Sbyte, Boolean };
        static ModuleDefMD module = null;

        static void Main(string[] args)
        {

            if (args.Count() != 1)
            {
                DisplayHelp();
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Error : specified file doesnt exists.");
                return;
            }

            //This dic will be filled with QUasar config values
            Dictionary<String, object> PROPERTIES = new Dictionary<String, object>();

            try
            {  //Load the module using Dnlib (for security reasons, NO LIVE DEBUGGING/NO ASSEMBLY LOADING)
                module = ModuleDefMD.Load(args[0]);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error : " + e.Message);
                return;
            }

            //Get All the type from the binary
            IEnumerable<TypeDef> types = module.GetTypes();

            //Browse all types to find the Main one. Config values are initialized in the constructor
            foreach (var type in types)
            {
                if (PROPERTIES.Count() > 0) { break; }

                try
                {

                    if (type.Fields.Count == 20 && type.Methods.Count == 3)
                    {
                        //We should be in "MainClass"
                        // Console.WriteLine(type);

                        //Get the constructor Body
                        MethodDef constructr = type.FindConstructors().First();
                        IList<Instruction> intrs = constructr.Body.Instructions;

                        if (intrs.Count == 0) { continue; }


                        //1) Fill the values
                        
                        string strvalue = "";
                        string fieldname = "";
                        int intvalue = 0;
                        sbyte sb = 0;
                        bool boleanvalue = false;
                        valtype VAL = valtype.Undefined;

                        foreach (var op in intrs)
                        {
                            //Console.WriteLine(op);

                            if (op.OpCode.OperandType == OperandType.InlineString)
                            {
                                strvalue = (string)op.Operand;
                                VAL = valtype.String;
                                continue;
                            }

                            if ((op.OpCode.OperandType == OperandType.InlineI))
                            {
                                intvalue = (int)op.Operand;
                                VAL = valtype.Integer;
                                continue;
                            }

                            if (op.OpCode.OperandType == OperandType.ShortInlineI)
                            {
                                sb = (sbyte)op.Operand;
                                VAL = valtype.Sbyte;
                                continue;
                            }


                            switch (op.OpCode.ToString())
                            {
                                case "ldc.i4.0":
                                    VAL = valtype.Boolean;
                                    boleanvalue = false;
                                    break;

                                case "ldc.i4.1":
                                    VAL = valtype.Boolean;
                                    boleanvalue = true;
                                    break;

                                default:
                                    break;

                            }


                            if (op.OpCode.OperandType == OperandType.InlineField)
                            {
                                fieldname = op.Operand.ToString();
                                int index = fieldname.IndexOf("::");
                                fieldname = fieldname.Substring(index + 2, fieldname.Length - index - 2);

                                switch (VAL)
                                {


                                    case valtype.String:
                                        PROPERTIES.Add(fieldname, strvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Integer:
                                        PROPERTIES.Add(fieldname, intvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Sbyte:
                                        PROPERTIES.Add(fieldname, sb);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Boolean:
                                        PROPERTIES.Add(fieldname, boleanvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;


                                }

                                VAL = valtype.Undefined;

                            }


                        } 


                        //2) Find the ENC KEY
                        // The Encryption key is used in the Main method of the Main class
                        // This class only has 3 methods : Main, cctor, ctor. One constructor is empty, we alreay know the other one so the main method is the last one

                        MethodDef M = null;
                        String ENCRYPTIONKEY = "";
                        foreach (MethodDef MD in type.Methods)
                        {
                            if (MD.Body.Instructions.Count > 0 && MD != constructr)
                            {
                                M = MD;
                                break;
                            }
                        }
                        intrs = M.Body.Instructions;


                        int counter = 0;

                        foreach (var op in intrs)
                        {
                            if (ENCRYPTIONKEY != "") { break; }

                            if (op.OpCode.OperandType == OperandType.InlineField)
                            {
                                counter++;

                                switch (counter)
                                {
                                    case 1:
                                        break;

                                    case 2:
                                        fieldname = op.Operand.ToString();
                                        int index = fieldname.IndexOf("::");
                                        fieldname = fieldname.Substring(index + 2, fieldname.Length - index - 2);

                                        if (PROPERTIES[fieldname] is String)
                                        {
                                            ENCRYPTIONKEY = (string)PROPERTIES[fieldname];

                                        }

                                        break;
                                }

                            }
                        } //ENCRYPTION KEY FOUND


                        //3)DISPLAY DECRYPTED VALUES

                        //Initialize encryption
                        AES.SetDefaultKey(ENCRYPTIONKEY);


                        foreach (KeyValuePair<String, object> KP in PROPERTIES)
                        {
                            string value = "";
                            try
                            {
                                value = KP.Value.ToString();

                                if ((KP.Value is String) && (KP.Key != fieldname))
                                {
                                    string tmp = AES.Decrypt((string)KP.Value); //AES.Decrypt returns "" if something was wrong (i.e string not encrypted.. Not all config is encrypted)
                                    if (!String.IsNullOrEmpty(tmp))
                                    {
                                        value = tmp;
                                    }
                                }

                            }
                            catch (Exception)
                            {

                            }
                            Console.WriteLine(KP.Key + " = " + value);
                        }

                        Console.ReadKey();
                        return;


                    }


                }
                catch (Exception)
                {


                }


            }





        }

        private static void DisplayHelp()
        {
            Console.WriteLine("Quasar Decryptor 1.0");
            Console.WriteLine("------------------------------------------");
            Console.WriteLine("Usage : QuasarDecryptor.exe filename.exe");
        }
    }
}
