package android.support.constraint.solver;

public class Cache {
    Pool<ArrayRow> arrayRowPool = new SimplePool(256);
    SolverVariable[] mIndexedVariables = new SolverVariable[32];
    Pool<SolverVariable> solverVariablePool = new SimplePool(256);
}
