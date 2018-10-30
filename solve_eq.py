from z3 import *

solver = Solver()

# Flag order
order=[7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]
flag={}
for i in order:
	flag[i] = BitVec("c_%d" % i,8)

#char constraints
for k in flag.keys():
	solver.add(flag[k] >= 32, flag[k] <= 126)
	
#equations
solver.add((flag[9] * flag[27])*((flag[23]-flag[18])^flag[29]) == 0x3fcf)
solver.add((flag[17]^flag[8])^(flag[1]-flag[22]) == 0x53)
solver.add((flag[30]-flag[25])*((flag[26]+flag[4])^flag[7]) == 0xffffe8f2)
solver.add(flag[15]-flag[28] == 0xb )
solver.add((flag[16]+flag[13])^flag[21] == 3)
solver.add((flag[1]-flag[16])+flag[21] == 0xb0)
solver.add(((flag[4]^flag[18])-(flag[17]+flag[28]))^flag[27] == 0xffffff39)
solver.add((flag[25]*flag[13])+((flag[7]^flag[30])*flag[8]) == 0x2701)
solver.add((flag[29]*flag[9])-flag[22] == 0x823)
solver.add((flag[15]+flag[23])-flag[26] == 0x6e)
solver.add((flag[29]+flag[4])+(flag[18]*flag[21]) == 0x15fe)
solver.add((flag[26]-flag[25])-(flag[7]+flag[13]) == 0xffffff4a)
solver.add((flag[9]^flag[22])*flag[30] == 0x1c20)
solver.add((flag[28]*flag[27])+(flag[15]*flag[8]) == 0x45d0)
solver.add((flag[23]-flag[1])-(flag[16]*flag[17]) == 0xffffeae0)
solver.add((flag[1]*flag[15])+(flag[13]*flag[28]) == 0x49c8)
solver.add((flag[29]+flag[26])*flag[25] == 0x3ac9)
solver.add((flag[18]+flag[7])*flag[30] == 0x2f76)
solver.add((flag[9]^flag[27])*flag[17] == 0x2760)
solver.add((flag[23]+flag[22])-flag[16] == 0x84)
solver.add((flag[4]*flag[8])+flag[21] == 0x995)

solution=''
if solver.check() == z3.sat:
    model=solver.model()
    for i in order:
        solution+=chr(model[flag[i]].as_signed_long())
print solution