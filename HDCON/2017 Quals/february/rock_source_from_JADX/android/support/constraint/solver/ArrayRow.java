package android.support.constraint.solver;

import android.support.constraint.solver.SolverVariable.Type;

public class ArrayRow {
    private static final boolean DEBUG = false;
    float constantValue = 0.0f;
    boolean isSimpleDefinition = false;
    boolean used = false;
    SolverVariable variable = null;
    final ArrayLinkedVariables variables;

    public ArrayRow(Cache cache) {
        this.variables = new ArrayLinkedVariables(this, cache);
    }

    void updateClientEquations() {
        this.variables.updateClientEquations(this);
    }

    boolean hasAtLeastOnePositiveVariable() {
        return this.variables.hasAtLeastOnePositiveVariable();
    }

    boolean hasKeyVariable() {
        return this.variable != null && (this.variable.mType == Type.UNRESTRICTED || this.constantValue >= 0.0f);
    }

    public String toString() {
        return toReadableString();
    }

    String toReadableString() {
        String s = "";
        if (this.variable == null) {
            s = s + "0";
        } else {
            s = s + this.variable;
        }
        s = s + " = ";
        boolean addedVariable = false;
        if (this.constantValue != 0.0f) {
            s = s + this.constantValue;
            addedVariable = true;
        }
        int count = this.variables.currentSize;
        for (int i = 0; i < count; i++) {
            SolverVariable v = this.variables.getVariable(i);
            if (v != null) {
                float amount = this.variables.getVariableValue(i);
                String name = v.toString();
                if (addedVariable) {
                    if (amount > 0.0f) {
                        s = s + " + ";
                    } else {
                        s = s + " - ";
                        amount *= -1.0f;
                    }
                } else if (amount < 0.0f) {
                    s = s + "- ";
                    amount *= -1.0f;
                }
                if (amount == 1.0f) {
                    s = s + name;
                } else {
                    s = s + amount + " " + name;
                }
                addedVariable = true;
            }
        }
        if (addedVariable) {
            return s;
        }
        return s + "0.0";
    }

    public void reset() {
        this.variable = null;
        this.variables.clear();
        this.constantValue = 0.0f;
        this.isSimpleDefinition = false;
    }

    boolean hasVariable(SolverVariable v) {
        return this.variables.containsKey(v);
    }

    ArrayRow createRowDefinition(SolverVariable variable, int value) {
        this.variable = variable;
        variable.computedValue = (float) value;
        this.constantValue = (float) value;
        this.isSimpleDefinition = true;
        return this;
    }

    public ArrayRow createRowEquals(SolverVariable variable, int value) {
        if (value < 0) {
            this.constantValue = (float) (value * -1);
            this.variables.put(variable, 1.0f);
        } else {
            this.constantValue = (float) value;
            this.variables.put(variable, -1.0f);
        }
        return this;
    }

    public ArrayRow createRowEquals(SolverVariable variableA, SolverVariable variableB, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = (float) m;
        }
        if (inverse) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
        } else {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
        }
        return this;
    }

    ArrayRow addSingleError(SolverVariable error, int sign) {
        this.variables.put(error, (float) sign);
        return this;
    }

    public ArrayRow createRowGreaterThan(SolverVariable variableA, SolverVariable variableB, SolverVariable slack, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = (float) m;
        }
        if (inverse) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(slack, -1.0f);
        } else {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.variables.put(slack, 1.0f);
        }
        return this;
    }

    public ArrayRow createRowLowerThan(SolverVariable variableA, SolverVariable variableB, SolverVariable slack, int margin) {
        boolean inverse = false;
        if (margin != 0) {
            int m = margin;
            if (m < 0) {
                m *= -1;
                inverse = true;
            }
            this.constantValue = (float) m;
        }
        if (inverse) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(slack, 1.0f);
        } else {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.variables.put(slack, -1.0f);
        }
        return this;
    }

    public ArrayRow createRowEqualDimension(float currentWeight, float totalWeights, float nextWeight, SolverVariable variableStartA, int marginStartA, SolverVariable variableEndA, int marginEndA, SolverVariable variableStartB, int marginStartB, SolverVariable variableEndB, int marginEndB) {
        if (totalWeights == 0.0f || currentWeight == nextWeight) {
            this.constantValue = (float) ((((-marginStartA) - marginEndA) + marginStartB) + marginEndB);
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, 1.0f);
            this.variables.put(variableStartB, -1.0f);
        } else {
            float w = (currentWeight / totalWeights) / (nextWeight / totalWeights);
            this.constantValue = (((float) ((-marginStartA) - marginEndA)) + (((float) marginStartB) * w)) + (((float) marginEndB) * w);
            this.variables.put(variableStartA, 1.0f);
            this.variables.put(variableEndA, -1.0f);
            this.variables.put(variableEndB, w);
            this.variables.put(variableStartB, -w);
        }
        return this;
    }

    ArrayRow createRowCentering(SolverVariable variableA, SolverVariable variableB, int marginA, float bias, SolverVariable variableC, SolverVariable variableD, int marginB) {
        if (variableB == variableC) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableD, 1.0f);
            this.variables.put(variableB, -2.0f);
        } else if (bias == 0.5f) {
            this.variables.put(variableA, 1.0f);
            this.variables.put(variableB, -1.0f);
            this.variables.put(variableC, -1.0f);
            this.variables.put(variableD, 1.0f);
            if (marginA > 0 || marginB > 0) {
                this.constantValue = (float) ((-marginA) + marginB);
            }
        } else if (bias <= 0.0f) {
            this.variables.put(variableA, -1.0f);
            this.variables.put(variableB, 1.0f);
            this.constantValue = (float) marginA;
        } else if (bias >= 1.0f) {
            this.variables.put(variableC, -1.0f);
            this.variables.put(variableD, 1.0f);
            this.constantValue = (float) marginB;
        } else {
            this.variables.put(variableA, (1.0f - bias) * 1.0f);
            this.variables.put(variableB, (1.0f - bias) * -1.0f);
            this.variables.put(variableC, -1.0f * bias);
            this.variables.put(variableD, 1.0f * bias);
            if (marginA > 0 || marginB > 0) {
                this.constantValue = (((float) (-marginA)) * (1.0f - bias)) + (((float) marginB) * bias);
            }
        }
        return this;
    }

    public ArrayRow addError(SolverVariable error1, SolverVariable error2) {
        this.variables.put(error1, 1.0f);
        this.variables.put(error2, -1.0f);
        return this;
    }

    ArrayRow createRowDimensionPercent(SolverVariable variableA, SolverVariable variableB, SolverVariable variableC, float percent) {
        this.variables.put(variableA, -1.0f);
        this.variables.put(variableB, 1.0f - percent);
        this.variables.put(variableC, percent);
        return this;
    }

    public ArrayRow createRowDimensionRatio(SolverVariable variableA, SolverVariable variableB, SolverVariable variableC, SolverVariable variableD, float ratio) {
        this.variables.put(variableA, -1.0f);
        this.variables.put(variableB, 1.0f);
        this.variables.put(variableC, ratio);
        this.variables.put(variableD, -ratio);
        return this;
    }

    int sizeInBytes() {
        int size = 0;
        if (this.variable != null) {
            size = 0 + 4;
        }
        return ((size + 4) + 4) + this.variables.sizeInBytes();
    }

    boolean updateRowWithEquation(ArrayRow definition) {
        this.variables.updateFromRow(this, definition);
        return true;
    }

    void ensurePositiveConstant() {
        if (this.constantValue < 0.0f) {
            this.constantValue *= -1.0f;
            this.variables.invert();
        }
    }

    void pickRowVariable() {
        SolverVariable pivotCandidate = this.variables.pickPivotCandidate();
        if (pivotCandidate != null) {
            pivot(pivotCandidate);
        }
        if (this.variables.currentSize == 0) {
            this.isSimpleDefinition = true;
        }
    }

    void pivot(SolverVariable v) {
        if (this.variable != null) {
            this.variables.put(this.variable, -1.0f);
            this.variable = null;
        }
        float amount = this.variables.remove(v) * -1.0f;
        this.variable = v;
        if (amount != 1.0f) {
            this.constantValue /= amount;
            this.variables.divideByAmount(amount);
        }
    }
}
