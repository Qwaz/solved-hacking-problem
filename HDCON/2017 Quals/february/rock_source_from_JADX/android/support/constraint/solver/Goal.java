package android.support.constraint.solver;

import android.support.constraint.solver.SolverVariable.Type;
import java.util.ArrayList;

public class Goal {
    ArrayList<SolverVariable> variables = new ArrayList();

    SolverVariable getPivotCandidate() {
        int count = this.variables.size();
        SolverVariable candidate = null;
        int strength = 0;
        for (int i = 0; i < count; i++) {
            SolverVariable element = (SolverVariable) this.variables.get(i);
            int k = 5;
            while (k >= 0) {
                float value = element.strengthVector[k];
                if (candidate == null && value < 0.0f && k >= strength) {
                    strength = k;
                    candidate = element;
                }
                if (value > 0.0f && k > strength) {
                    strength = k;
                    candidate = null;
                }
                k--;
            }
        }
        return candidate;
    }

    private void initFromSystemErrors(LinearSystem system) {
        this.variables.clear();
        for (int i = 1; i < system.mNumColumns; i++) {
            SolverVariable variable = system.mCache.mIndexedVariables[i];
            for (int j = 0; j < 6; j++) {
                variable.strengthVector[j] = 0.0f;
            }
            variable.strengthVector[variable.strength] = 1.0f;
            if (variable.mType == Type.ERROR) {
                this.variables.add(variable);
            }
        }
    }

    void updateFromSystem(LinearSystem system) {
        initFromSystemErrors(system);
        int count = this.variables.size();
        for (int i = 0; i < count; i++) {
            SolverVariable element = (SolverVariable) this.variables.get(i);
            if (element.definitionId != -1) {
                ArrayLinkedVariables variables = system.getRow(element.definitionId).variables;
                int size = variables.currentSize;
                for (int j = 0; j < size; j++) {
                    SolverVariable var = variables.getVariable(j);
                    if (var != null) {
                        float value = variables.getVariableValue(j);
                        for (int k = 0; k < 6; k++) {
                            float[] fArr = var.strengthVector;
                            fArr[k] = fArr[k] + (element.strengthVector[k] * value);
                        }
                        if (!this.variables.contains(var)) {
                            this.variables.add(var);
                        }
                    }
                }
                element.clearStrengths();
            }
        }
    }

    public String toString() {
        String representation = "Goal: ";
        int count = this.variables.size();
        for (int i = 0; i < count; i++) {
            representation = representation + ((SolverVariable) this.variables.get(i)).strengthsToString();
        }
        return representation;
    }
}
