package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.widgets.ConstraintWidget.DimensionBehaviour;

public class Optimizer {
    static void applyDirectResolutionHorizontalChain(ConstraintWidgetContainer container, LinearSystem system, int numMatchConstraints, ConstraintWidget widget) {
        ConstraintWidget firstWidget = widget;
        int widgetSize = 0;
        ConstraintWidget previous = null;
        int count = 0;
        float totalWeights = 0.0f;
        while (widget != null) {
            if (!(widget.getVisibility() == 8)) {
                count++;
                if (widget.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                    widgetSize = ((widgetSize + widget.getWidth()) + (widget.mLeft.mTarget != null ? widget.mLeft.getMargin() : 0)) + (widget.mRight.mTarget != null ? widget.mRight.getMargin() : 0);
                } else {
                    totalWeights += widget.mHorizontalWeight;
                }
            }
            previous = widget;
            widget = widget.mRight.mTarget != null ? widget.mRight.mTarget.mOwner : null;
            if (widget != null && (widget.mLeft.mTarget == null || !(widget.mLeft.mTarget == null || widget.mLeft.mTarget.mOwner == previous))) {
                widget = null;
            }
        }
        int lastPosition = 0;
        if (previous != null) {
            lastPosition = previous.mRight.mTarget != null ? previous.mRight.mTarget.mOwner.getX() : 0;
            if (previous.mRight.mTarget != null && previous.mRight.mTarget.mOwner == container) {
                lastPosition = container.getRight();
            }
        }
        float spreadSpace = ((float) (lastPosition - 0)) - ((float) widgetSize);
        float split = spreadSpace / ((float) (count + 1));
        widget = firstWidget;
        float currentPosition = 0.0f;
        if (numMatchConstraints == 0) {
            currentPosition = split;
        } else {
            split = spreadSpace / ((float) numMatchConstraints);
        }
        while (widget != null) {
            int left = widget.mLeft.mTarget != null ? widget.mLeft.getMargin() : 0;
            int right = widget.mRight.mTarget != null ? widget.mRight.getMargin() : 0;
            if (widget.getVisibility() != 8) {
                currentPosition += (float) left;
                system.addEquality(widget.mLeft.mSolverVariable, (int) (0.5f + currentPosition));
                if (widget.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                    currentPosition += (float) widget.getWidth();
                } else if (totalWeights == 0.0f) {
                    currentPosition += (split - ((float) left)) - ((float) right);
                } else {
                    currentPosition += (((widget.mHorizontalWeight * spreadSpace) / totalWeights) - ((float) left)) - ((float) right);
                }
                system.addEquality(widget.mRight.mSolverVariable, (int) (0.5f + currentPosition));
                if (numMatchConstraints == 0) {
                    currentPosition += split;
                }
                currentPosition += (float) right;
            } else {
                float position = currentPosition - (split / 2.0f);
                system.addEquality(widget.mLeft.mSolverVariable, (int) (0.5f + position));
                system.addEquality(widget.mRight.mSolverVariable, (int) (0.5f + position));
            }
            previous = widget;
            widget = widget.mRight.mTarget != null ? widget.mRight.mTarget.mOwner : null;
            if (!(widget == null || widget.mLeft.mTarget == null || widget.mLeft.mTarget.mOwner == previous)) {
                widget = null;
            }
            if (widget == container) {
                widget = null;
            }
        }
    }

    static void applyDirectResolutionVerticalChain(ConstraintWidgetContainer container, LinearSystem system, int numMatchConstraints, ConstraintWidget widget) {
        ConstraintWidget firstWidget = widget;
        int widgetSize = 0;
        ConstraintWidget previous = null;
        int count = 0;
        float totalWeights = 0.0f;
        while (widget != null) {
            if (!(widget.getVisibility() == 8)) {
                count++;
                if (widget.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                    widgetSize = ((widgetSize + widget.getHeight()) + (widget.mTop.mTarget != null ? widget.mTop.getMargin() : 0)) + (widget.mBottom.mTarget != null ? widget.mBottom.getMargin() : 0);
                } else {
                    totalWeights += widget.mVerticalWeight;
                }
            }
            previous = widget;
            widget = widget.mBottom.mTarget != null ? widget.mBottom.mTarget.mOwner : null;
            if (widget != null && (widget.mTop.mTarget == null || !(widget.mTop.mTarget == null || widget.mTop.mTarget.mOwner == previous))) {
                widget = null;
            }
        }
        int lastPosition = 0;
        if (previous != null) {
            lastPosition = previous.mBottom.mTarget != null ? previous.mBottom.mTarget.mOwner.getX() : 0;
            if (previous.mBottom.mTarget != null && previous.mBottom.mTarget.mOwner == container) {
                lastPosition = container.getBottom();
            }
        }
        float spreadSpace = ((float) (lastPosition - 0)) - ((float) widgetSize);
        float split = spreadSpace / ((float) (count + 1));
        widget = firstWidget;
        float currentPosition = 0.0f;
        if (numMatchConstraints == 0) {
            currentPosition = split;
        } else {
            split = spreadSpace / ((float) numMatchConstraints);
        }
        while (widget != null) {
            int top = widget.mTop.mTarget != null ? widget.mTop.getMargin() : 0;
            int bottom = widget.mBottom.mTarget != null ? widget.mBottom.getMargin() : 0;
            if (widget.getVisibility() != 8) {
                currentPosition += (float) top;
                system.addEquality(widget.mTop.mSolverVariable, (int) (0.5f + currentPosition));
                if (widget.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                    currentPosition += (float) widget.getHeight();
                } else if (totalWeights == 0.0f) {
                    currentPosition += (split - ((float) top)) - ((float) bottom);
                } else {
                    currentPosition += (((widget.mVerticalWeight * spreadSpace) / totalWeights) - ((float) top)) - ((float) bottom);
                }
                system.addEquality(widget.mBottom.mSolverVariable, (int) (0.5f + currentPosition));
                if (numMatchConstraints == 0) {
                    currentPosition += split;
                }
                currentPosition += (float) bottom;
            } else {
                float position = currentPosition - (split / 2.0f);
                system.addEquality(widget.mTop.mSolverVariable, (int) (0.5f + position));
                system.addEquality(widget.mBottom.mSolverVariable, (int) (0.5f + position));
            }
            previous = widget;
            widget = widget.mBottom.mTarget != null ? widget.mBottom.mTarget.mOwner : null;
            if (!(widget == null || widget.mTop.mTarget == null || widget.mTop.mTarget.mOwner == previous)) {
                widget = null;
            }
            if (widget == container) {
                widget = null;
            }
        }
    }

    static void checkMatchParent(ConstraintWidgetContainer container, LinearSystem system, ConstraintWidget widget) {
        if (container.mHorizontalDimensionBehaviour != DimensionBehaviour.WRAP_CONTENT && widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
            widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
            widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
            int left = widget.mLeft.mMargin;
            int right = container.getWidth() - widget.mRight.mMargin;
            system.addEquality(widget.mLeft.mSolverVariable, left);
            system.addEquality(widget.mRight.mSolverVariable, right);
            widget.setHorizontalDimension(left, right);
            widget.mHorizontalResolution = 2;
        }
        if (container.mVerticalDimensionBehaviour != DimensionBehaviour.WRAP_CONTENT && widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
            widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
            widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
            int top = widget.mTop.mMargin;
            int bottom = container.getHeight() - widget.mBottom.mMargin;
            system.addEquality(widget.mTop.mSolverVariable, top);
            system.addEquality(widget.mBottom.mSolverVariable, bottom);
            if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
            }
            widget.setVerticalDimension(top, bottom);
            widget.mVerticalResolution = 2;
        }
    }

    static void checkHorizontalSimpleDependency(ConstraintWidgetContainer container, LinearSystem system, ConstraintWidget widget) {
        if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
            widget.mHorizontalResolution = 1;
        } else if (container.mHorizontalDimensionBehaviour != DimensionBehaviour.WRAP_CONTENT && widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
            widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
            widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
            left = widget.mLeft.mMargin;
            right = container.getWidth() - widget.mRight.mMargin;
            system.addEquality(widget.mLeft.mSolverVariable, left);
            system.addEquality(widget.mRight.mSolverVariable, right);
            widget.setHorizontalDimension(left, right);
            widget.mHorizontalResolution = 2;
        } else if (widget.mLeft.mTarget == null || widget.mRight.mTarget == null) {
            if (widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner == container) {
                left = widget.mLeft.getMargin();
                right = left + widget.getWidth();
                widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                system.addEquality(widget.mLeft.mSolverVariable, left);
                system.addEquality(widget.mRight.mSolverVariable, right);
                widget.mHorizontalResolution = 2;
                widget.setHorizontalDimension(left, right);
            } else if (widget.mRight.mTarget != null && widget.mRight.mTarget.mOwner == container) {
                widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                right = container.getWidth() - widget.mRight.getMargin();
                left = right - widget.getWidth();
                system.addEquality(widget.mLeft.mSolverVariable, left);
                system.addEquality(widget.mRight.mSolverVariable, right);
                widget.mHorizontalResolution = 2;
                widget.setHorizontalDimension(left, right);
            } else if (widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner.mHorizontalResolution == 2) {
                target = widget.mLeft.mTarget.mSolverVariable;
                widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                left = (int) ((target.computedValue + ((float) widget.mLeft.getMargin())) + 0.5f);
                right = left + widget.getWidth();
                system.addEquality(widget.mLeft.mSolverVariable, left);
                system.addEquality(widget.mRight.mSolverVariable, right);
                widget.mHorizontalResolution = 2;
                widget.setHorizontalDimension(left, right);
            } else if (widget.mRight.mTarget == null || widget.mRight.mTarget.mOwner.mHorizontalResolution != 2) {
                boolean hasLeft = widget.mLeft.mTarget != null;
                boolean hasRight = widget.mRight.mTarget != null;
                if (!hasLeft && !hasRight) {
                    if (widget instanceof Guideline) {
                        Guideline guideline = (Guideline) widget;
                        if (guideline.getOrientation() == 1) {
                            float position;
                            widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                            widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                            if (guideline.getRelativeBegin() != -1) {
                                position = (float) guideline.getRelativeBegin();
                            } else if (guideline.getRelativeEnd() != -1) {
                                position = (float) (container.getWidth() - guideline.getRelativeEnd());
                            } else {
                                position = ((float) container.getWidth()) * guideline.getRelativePercent();
                            }
                            int value = (int) (0.5f + position);
                            system.addEquality(widget.mLeft.mSolverVariable, value);
                            system.addEquality(widget.mRight.mSolverVariable, value);
                            widget.mHorizontalResolution = 2;
                            widget.mVerticalResolution = 2;
                            widget.setHorizontalDimension(value, value);
                            widget.setVerticalDimension(0, container.getHeight());
                            return;
                        }
                        return;
                    }
                    widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                    widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                    left = widget.getX();
                    right = left + widget.getWidth();
                    system.addEquality(widget.mLeft.mSolverVariable, left);
                    system.addEquality(widget.mRight.mSolverVariable, right);
                    widget.mHorizontalResolution = 2;
                }
            } else {
                target = widget.mRight.mTarget.mSolverVariable;
                widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
                widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
                right = (int) ((target.computedValue - ((float) widget.mRight.getMargin())) + 0.5f);
                left = right - widget.getWidth();
                system.addEquality(widget.mLeft.mSolverVariable, left);
                system.addEquality(widget.mRight.mSolverVariable, right);
                widget.mHorizontalResolution = 2;
                widget.setHorizontalDimension(left, right);
            }
        } else if (widget.mLeft.mTarget.mOwner == container && widget.mRight.mTarget.mOwner == container) {
            int leftMargin = widget.mLeft.getMargin();
            int rightMargin = widget.mRight.getMargin();
            if (container.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                left = leftMargin;
                right = container.getWidth() - rightMargin;
            } else {
                left = leftMargin + ((int) ((((float) (((container.getWidth() - leftMargin) - rightMargin) - widget.getWidth())) * widget.mHorizontalBiasPercent) + 0.5f));
                right = left + widget.getWidth();
            }
            widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
            widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
            system.addEquality(widget.mLeft.mSolverVariable, left);
            system.addEquality(widget.mRight.mSolverVariable, right);
            widget.mHorizontalResolution = 2;
            widget.setHorizontalDimension(left, right);
        } else {
            widget.mHorizontalResolution = 1;
        }
    }

    static void checkVerticalSimpleDependency(ConstraintWidgetContainer container, LinearSystem system, ConstraintWidget widget) {
        if (widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
            widget.mVerticalResolution = 1;
        } else if (container.mVerticalDimensionBehaviour != DimensionBehaviour.WRAP_CONTENT && widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
            widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
            widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
            top = widget.mTop.mMargin;
            bottom = container.getHeight() - widget.mBottom.mMargin;
            system.addEquality(widget.mTop.mSolverVariable, top);
            system.addEquality(widget.mBottom.mSolverVariable, bottom);
            if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
            }
            widget.setVerticalDimension(top, bottom);
            widget.mVerticalResolution = 2;
        } else if (widget.mTop.mTarget == null || widget.mBottom.mTarget == null) {
            if (widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner == container) {
                top = widget.mTop.getMargin();
                bottom = top + widget.getHeight();
                widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                system.addEquality(widget.mTop.mSolverVariable, top);
                system.addEquality(widget.mBottom.mSolverVariable, bottom);
                if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                    widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                    system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                }
                widget.mVerticalResolution = 2;
                widget.setVerticalDimension(top, bottom);
            } else if (widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner == container) {
                widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                bottom = container.getHeight() - widget.mBottom.getMargin();
                top = bottom - widget.getHeight();
                system.addEquality(widget.mTop.mSolverVariable, top);
                system.addEquality(widget.mBottom.mSolverVariable, bottom);
                if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                    widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                    system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                }
                widget.mVerticalResolution = 2;
                widget.setVerticalDimension(top, bottom);
            } else if (widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner.mVerticalResolution == 2) {
                target = widget.mTop.mTarget.mSolverVariable;
                widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                top = (int) ((target.computedValue + ((float) widget.mTop.getMargin())) + 0.5f);
                bottom = top + widget.getHeight();
                system.addEquality(widget.mTop.mSolverVariable, top);
                system.addEquality(widget.mBottom.mSolverVariable, bottom);
                if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                    widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                    system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                }
                widget.mVerticalResolution = 2;
                widget.setVerticalDimension(top, bottom);
            } else if (widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner.mVerticalResolution == 2) {
                target = widget.mBottom.mTarget.mSolverVariable;
                widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                bottom = (int) ((target.computedValue - ((float) widget.mBottom.getMargin())) + 0.5f);
                top = bottom - widget.getHeight();
                system.addEquality(widget.mTop.mSolverVariable, top);
                system.addEquality(widget.mBottom.mSolverVariable, bottom);
                if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                    widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                    system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                }
                widget.mVerticalResolution = 2;
                widget.setVerticalDimension(top, bottom);
            } else if (widget.mBaseline.mTarget == null || widget.mBaseline.mTarget.mOwner.mVerticalResolution != 2) {
                boolean hasBaseline = widget.mBaseline.mTarget != null;
                boolean hasTop = widget.mTop.mTarget != null;
                boolean hasBottom = widget.mBottom.mTarget != null;
                if (!hasBaseline && !hasTop && !hasBottom) {
                    if (widget instanceof Guideline) {
                        Guideline guideline = (Guideline) widget;
                        if (guideline.getOrientation() == 0) {
                            float position;
                            widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                            widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                            if (guideline.getRelativeBegin() != -1) {
                                position = (float) guideline.getRelativeBegin();
                            } else if (guideline.getRelativeEnd() != -1) {
                                position = (float) (container.getHeight() - guideline.getRelativeEnd());
                            } else {
                                position = ((float) container.getHeight()) * guideline.getRelativePercent();
                            }
                            int value = (int) (0.5f + position);
                            system.addEquality(widget.mTop.mSolverVariable, value);
                            system.addEquality(widget.mBottom.mSolverVariable, value);
                            widget.mVerticalResolution = 2;
                            widget.mHorizontalResolution = 2;
                            widget.setVerticalDimension(value, value);
                            widget.setHorizontalDimension(0, container.getWidth());
                            return;
                        }
                        return;
                    }
                    widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                    widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                    top = widget.getY();
                    bottom = top + widget.getHeight();
                    system.addEquality(widget.mTop.mSolverVariable, top);
                    system.addEquality(widget.mBottom.mSolverVariable, bottom);
                    if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                        widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                        system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                    }
                    widget.mVerticalResolution = 2;
                }
            } else {
                target = widget.mBaseline.mTarget.mSolverVariable;
                widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
                widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
                top = (int) ((target.computedValue - ((float) widget.mBaselineDistance)) + 0.5f);
                bottom = top + widget.getHeight();
                system.addEquality(widget.mTop.mSolverVariable, top);
                system.addEquality(widget.mBottom.mSolverVariable, bottom);
                widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
                widget.mVerticalResolution = 2;
                widget.setVerticalDimension(top, bottom);
            }
        } else if (widget.mTop.mTarget.mOwner == container && widget.mBottom.mTarget.mOwner == container) {
            int topMargin = widget.mTop.getMargin();
            int bottomMargin = widget.mBottom.getMargin();
            if (container.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                top = topMargin;
                bottom = top + widget.getHeight();
            } else {
                top = (int) ((((float) topMargin) + (((float) (((container.getHeight() - topMargin) - bottomMargin) - widget.getHeight())) * widget.mVerticalBiasPercent)) + 0.5f);
                bottom = top + widget.getHeight();
            }
            widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
            widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
            system.addEquality(widget.mTop.mSolverVariable, top);
            system.addEquality(widget.mBottom.mSolverVariable, bottom);
            if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
            }
            widget.mVerticalResolution = 2;
            widget.setVerticalDimension(top, bottom);
        } else {
            widget.mVerticalResolution = 1;
        }
    }
}
