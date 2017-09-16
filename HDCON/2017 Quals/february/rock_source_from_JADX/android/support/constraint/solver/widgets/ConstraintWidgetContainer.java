package android.support.constraint.solver.widgets;

import android.support.constraint.solver.ArrayRow;
import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.SolverVariable;
import android.support.constraint.solver.widgets.ConstraintAnchor.Type;
import android.support.constraint.solver.widgets.ConstraintWidget.DimensionBehaviour;
import java.util.ArrayList;
import java.util.Arrays;

public class ConstraintWidgetContainer extends WidgetContainer {
    static boolean ALLOW_ROOT_GROUP = USE_SNAPSHOT;
    private static final int CHAIN_FIRST = 0;
    private static final int CHAIN_FIRST_VISIBLE = 2;
    private static final int CHAIN_LAST = 1;
    private static final int CHAIN_LAST_VISIBLE = 3;
    private static final boolean DEBUG = false;
    private static final boolean DEBUG_LAYOUT = false;
    private static final boolean DEBUG_OPTIMIZE = false;
    private static final int FLAG_CHAIN_DANGLING = 1;
    private static final int FLAG_CHAIN_OPTIMIZE = 0;
    private static final int FLAG_RECOMPUTE_BOUNDS = 2;
    private static final int MAX_ITERATIONS = 8;
    public static final int OPTIMIZATION_ALL = 2;
    public static final int OPTIMIZATION_BASIC = 4;
    public static final int OPTIMIZATION_CHAIN = 8;
    public static final int OPTIMIZATION_NONE = 1;
    private static final boolean USE_SNAPSHOT = true;
    private static final boolean USE_THREAD = false;
    private boolean[] flags;
    protected LinearSystem mBackgroundSystem;
    private ConstraintWidget[] mChainEnds;
    private boolean mHeightMeasuredTooSmall;
    private ConstraintWidget[] mHorizontalChainsArray;
    private int mHorizontalChainsSize;
    private ConstraintWidget[] mMatchConstraintsChainedWidgets;
    private int mOptimizationLevel;
    int mPaddingBottom;
    int mPaddingLeft;
    int mPaddingRight;
    int mPaddingTop;
    private Snapshot mSnapshot;
    protected LinearSystem mSystem;
    private ConstraintWidget[] mVerticalChainsArray;
    private int mVerticalChainsSize;
    private boolean mWidthMeasuredTooSmall;
    int mWrapHeight;
    int mWrapWidth;

    public ConstraintWidgetContainer() {
        this.mSystem = new LinearSystem();
        this.mBackgroundSystem = null;
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mMatchConstraintsChainedWidgets = new ConstraintWidget[4];
        this.mVerticalChainsArray = new ConstraintWidget[4];
        this.mHorizontalChainsArray = new ConstraintWidget[4];
        this.mOptimizationLevel = 2;
        this.flags = new boolean[3];
        this.mChainEnds = new ConstraintWidget[4];
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
    }

    public ConstraintWidgetContainer(int x, int y, int width, int height) {
        super(x, y, width, height);
        this.mSystem = new LinearSystem();
        this.mBackgroundSystem = null;
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mMatchConstraintsChainedWidgets = new ConstraintWidget[4];
        this.mVerticalChainsArray = new ConstraintWidget[4];
        this.mHorizontalChainsArray = new ConstraintWidget[4];
        this.mOptimizationLevel = 2;
        this.flags = new boolean[3];
        this.mChainEnds = new ConstraintWidget[4];
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
    }

    public ConstraintWidgetContainer(int width, int height) {
        super(width, height);
        this.mSystem = new LinearSystem();
        this.mBackgroundSystem = null;
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
        this.mMatchConstraintsChainedWidgets = new ConstraintWidget[4];
        this.mVerticalChainsArray = new ConstraintWidget[4];
        this.mHorizontalChainsArray = new ConstraintWidget[4];
        this.mOptimizationLevel = 2;
        this.flags = new boolean[3];
        this.mChainEnds = new ConstraintWidget[4];
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
    }

    public void setOptimizationLevel(int value) {
        this.mOptimizationLevel = value;
    }

    public String getType() {
        return "ConstraintLayout";
    }

    public void reset() {
        this.mSystem.reset();
        this.mPaddingLeft = 0;
        this.mPaddingRight = 0;
        this.mPaddingTop = 0;
        this.mPaddingBottom = 0;
        super.reset();
    }

    public boolean isWidthMeasuredTooSmall() {
        return this.mWidthMeasuredTooSmall;
    }

    public boolean isHeightMeasuredTooSmall() {
        return this.mHeightMeasuredTooSmall;
    }

    public static ConstraintWidgetContainer createContainer(ConstraintWidgetContainer container, String name, ArrayList<ConstraintWidget> widgets, int padding) {
        Rectangle bounds = WidgetContainer.getBounds(widgets);
        if (bounds.width == 0 || bounds.height == 0) {
            return null;
        }
        if (padding > 0) {
            int maxPadding = Math.min(bounds.f4x, bounds.f5y);
            if (padding > maxPadding) {
                padding = maxPadding;
            }
            bounds.grow(padding, padding);
        }
        container.setOrigin(bounds.f4x, bounds.f5y);
        container.setDimension(bounds.width, bounds.height);
        container.setDebugName(name);
        ConstraintWidget parent = ((ConstraintWidget) widgets.get(0)).getParent();
        int widgetsSize = widgets.size();
        for (int i = 0; i < widgetsSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) widgets.get(i);
            if (widget.getParent() == parent) {
                container.add(widget);
                widget.setX(widget.getX() - bounds.f4x);
                widget.setY(widget.getY() - bounds.f5y);
            }
        }
        return container;
    }

    public boolean addChildrenToSolver(LinearSystem system, int group) {
        addToSolver(system, group);
        int count = this.mChildren.size();
        boolean setMatchParent = false;
        if (this.mOptimizationLevel != 2 && this.mOptimizationLevel != 4) {
            setMatchParent = USE_SNAPSHOT;
        } else if (optimize(system)) {
            return false;
        }
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof ConstraintWidgetContainer) {
                DimensionBehaviour horizontalBehaviour = widget.mHorizontalDimensionBehaviour;
                DimensionBehaviour verticalBehaviour = widget.mVerticalDimensionBehaviour;
                if (horizontalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
                if (verticalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
                widget.addToSolver(system, group);
                if (horizontalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(horizontalBehaviour);
                }
                if (verticalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(verticalBehaviour);
                }
            } else {
                if (setMatchParent) {
                    Optimizer.checkMatchParent(this, system, widget);
                }
                widget.addToSolver(system, group);
            }
        }
        if (this.mHorizontalChainsSize > 0) {
            applyHorizontalChain(system);
        }
        if (this.mVerticalChainsSize > 0) {
            applyVerticalChain(system);
        }
        return USE_SNAPSHOT;
    }

    private boolean optimize(LinearSystem system) {
        int i;
        int count = this.mChildren.size();
        boolean done = false;
        int dv = 0;
        int dh = 0;
        int n = 0;
        for (i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            widget.mHorizontalResolution = -1;
            widget.mVerticalResolution = -1;
            if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT || widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                widget.mHorizontalResolution = 1;
                widget.mVerticalResolution = 1;
            }
        }
        while (!done) {
            int prev = dv;
            int preh = dh;
            dv = 0;
            dh = 0;
            n++;
            for (i = 0; i < count; i++) {
                widget = (ConstraintWidget) this.mChildren.get(i);
                if (widget.mHorizontalResolution == -1) {
                    if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                        widget.mHorizontalResolution = 1;
                    } else {
                        Optimizer.checkHorizontalSimpleDependency(this, system, widget);
                    }
                }
                if (widget.mVerticalResolution == -1) {
                    if (this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                        widget.mVerticalResolution = 1;
                    } else {
                        Optimizer.checkVerticalSimpleDependency(this, system, widget);
                    }
                }
                if (widget.mVerticalResolution == -1) {
                    dv++;
                }
                if (widget.mHorizontalResolution == -1) {
                    dh++;
                }
            }
            if (dv == 0 && dh == 0) {
                done = USE_SNAPSHOT;
            } else if (prev == dv && preh == dh) {
                done = USE_SNAPSHOT;
            }
        }
        int sh = 0;
        int sv = 0;
        for (i = 0; i < count; i++) {
            widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget.mHorizontalResolution == 1 || widget.mHorizontalResolution == -1) {
                sh++;
            }
            if (widget.mVerticalResolution == 1 || widget.mVerticalResolution == -1) {
                sv++;
            }
        }
        if (sh == 0 && sv == 0) {
            return USE_SNAPSHOT;
        }
        return false;
    }

    private void applyHorizontalChain(LinearSystem system) {
        for (int i = 0; i < this.mHorizontalChainsSize; i++) {
            ConstraintWidget first = this.mHorizontalChainsArray[i];
            int numMatchConstraints = countMatchConstraintsChainedWidgets(system, this.mChainEnds, this.mHorizontalChainsArray[i], 0, this.flags);
            ConstraintWidget currentWidget = this.mChainEnds[2];
            if (currentWidget != null) {
                if (this.flags[1]) {
                    int x = first.getDrawX();
                    while (currentWidget != null) {
                        system.addEquality(currentWidget.mLeft.mSolverVariable, x);
                        x += (currentWidget.mLeft.getMargin() + currentWidget.getWidth()) + currentWidget.mRight.getMargin();
                        currentWidget = currentWidget.mHorizontalNextWidget;
                    }
                } else {
                    boolean isChainSpread = first.mHorizontalChainStyle == 0 ? USE_SNAPSHOT : false;
                    boolean isChainPacked = first.mHorizontalChainStyle == 2 ? USE_SNAPSHOT : false;
                    ConstraintWidget widget = first;
                    boolean isWrapContent = this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT ? USE_SNAPSHOT : false;
                    if ((this.mOptimizationLevel == 2 || this.mOptimizationLevel == 8) && this.flags[0] && widget.mHorizontalChainFixedPosition && !isChainPacked && !isWrapContent && first.mHorizontalChainStyle == 0) {
                        Optimizer.applyDirectResolutionHorizontalChain(this, system, numMatchConstraints, widget);
                    } else if (numMatchConstraints == 0 || isChainPacked) {
                        ConstraintAnchor left;
                        ConstraintAnchor right;
                        SolverVariable leftTarget;
                        ConstraintWidget previousVisibleWidget = null;
                        ConstraintWidget lastWidget = null;
                        ConstraintWidget firstVisibleWidget = currentWidget;
                        boolean isLast = false;
                        while (currentWidget != null) {
                            ConstraintWidget next = currentWidget.mHorizontalNextWidget;
                            if (next == null) {
                                lastWidget = this.mChainEnds[1];
                                isLast = USE_SNAPSHOT;
                            }
                            if (isChainPacked) {
                                left = currentWidget.mLeft;
                                margin = left.getMargin();
                                if (previousVisibleWidget != null) {
                                    margin += previousVisibleWidget.mRight.getMargin();
                                }
                                strength = 1;
                                if (firstVisibleWidget != currentWidget) {
                                    strength = 3;
                                }
                                system.addGreaterThan(left.mSolverVariable, left.mTarget.mSolverVariable, margin, strength);
                                if (currentWidget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    right = currentWidget.mRight;
                                    if (currentWidget.mMatchConstraintDefaultWidth == 1) {
                                        system.addEquality(right.mSolverVariable, left.mSolverVariable, Math.max(currentWidget.mMatchConstraintMinWidth, currentWidget.getWidth()), 3);
                                    } else {
                                        system.addGreaterThan(left.mSolverVariable, left.mTarget.mSolverVariable, left.mMargin, 3);
                                        system.addLowerThan(right.mSolverVariable, left.mSolverVariable, currentWidget.mMatchConstraintMinWidth, 3);
                                    }
                                }
                            } else if (isChainSpread || !isLast || previousVisibleWidget == null) {
                                if (isChainSpread || isLast || previousVisibleWidget != null) {
                                    left = currentWidget.mLeft;
                                    right = currentWidget.mRight;
                                    leftMargin = left.getMargin();
                                    rightMargin = right.getMargin();
                                    system.addGreaterThan(left.mSolverVariable, left.mTarget.mSolverVariable, leftMargin, 1);
                                    system.addLowerThan(right.mSolverVariable, right.mTarget.mSolverVariable, -rightMargin, 1);
                                    leftTarget = left.mTarget != null ? left.mTarget.mSolverVariable : null;
                                    if (previousVisibleWidget == null) {
                                        leftTarget = first.mLeft.mTarget != null ? first.mLeft.mTarget.mSolverVariable : null;
                                    }
                                    if (next == null) {
                                        next = lastWidget.mRight.mTarget != null ? lastWidget.mRight.mTarget.mOwner : null;
                                    }
                                    if (next != null) {
                                        rightTarget = next.mLeft.mSolverVariable;
                                        if (isLast) {
                                            rightTarget = lastWidget.mRight.mTarget != null ? lastWidget.mRight.mTarget.mSolverVariable : null;
                                        }
                                        if (!(leftTarget == null || rightTarget == null)) {
                                            system.addCentering(left.mSolverVariable, leftTarget, leftMargin, 0.5f, rightTarget, right.mSolverVariable, rightMargin, 4);
                                        }
                                    }
                                } else if (currentWidget.mLeft.mTarget == null) {
                                    system.addEquality(currentWidget.mLeft.mSolverVariable, currentWidget.getDrawX());
                                } else {
                                    system.addEquality(currentWidget.mLeft.mSolverVariable, first.mLeft.mTarget.mSolverVariable, currentWidget.mLeft.getMargin(), 5);
                                }
                            } else if (currentWidget.mRight.mTarget == null) {
                                system.addEquality(currentWidget.mRight.mSolverVariable, currentWidget.getDrawRight());
                            } else {
                                system.addEquality(currentWidget.mRight.mSolverVariable, lastWidget.mRight.mTarget.mSolverVariable, -currentWidget.mRight.getMargin(), 5);
                            }
                            previousVisibleWidget = currentWidget;
                            if (isLast) {
                                currentWidget = null;
                            } else {
                                currentWidget = next;
                            }
                        }
                        if (isChainPacked) {
                            left = firstVisibleWidget.mLeft;
                            right = lastWidget.mRight;
                            leftMargin = left.getMargin();
                            rightMargin = right.getMargin();
                            leftTarget = first.mLeft.mTarget != null ? first.mLeft.mTarget.mSolverVariable : null;
                            rightTarget = lastWidget.mRight.mTarget != null ? lastWidget.mRight.mTarget.mSolverVariable : null;
                            if (!(leftTarget == null || rightTarget == null)) {
                                system.addLowerThan(right.mSolverVariable, rightTarget, -rightMargin, 1);
                                system.addCentering(left.mSolverVariable, leftTarget, leftMargin, first.mHorizontalBiasPercent, rightTarget, right.mSolverVariable, rightMargin, 4);
                            }
                        }
                    } else {
                        ConstraintWidget previous = null;
                        float totalWeights = 0.0f;
                        while (currentWidget != null) {
                            if (currentWidget.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                                margin = currentWidget.mLeft.getMargin();
                                if (previous != null) {
                                    margin += previous.mRight.getMargin();
                                }
                                strength = 3;
                                if (currentWidget.mLeft.mTarget.mOwner.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    strength = 2;
                                }
                                system.addGreaterThan(currentWidget.mLeft.mSolverVariable, currentWidget.mLeft.mTarget.mSolverVariable, margin, strength);
                                margin = currentWidget.mRight.getMargin();
                                if (currentWidget.mRight.mTarget.mOwner.mLeft.mTarget != null && currentWidget.mRight.mTarget.mOwner.mLeft.mTarget.mOwner == currentWidget) {
                                    margin += currentWidget.mRight.mTarget.mOwner.mLeft.getMargin();
                                }
                                strength = 3;
                                if (currentWidget.mRight.mTarget.mOwner.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    strength = 2;
                                }
                                system.addLowerThan(currentWidget.mRight.mSolverVariable, currentWidget.mRight.mTarget.mSolverVariable, -margin, strength);
                            } else {
                                totalWeights += currentWidget.mHorizontalWeight;
                                margin = 0;
                                if (currentWidget.mRight.mTarget != null) {
                                    margin = currentWidget.mRight.getMargin();
                                    if (currentWidget != this.mChainEnds[3]) {
                                        margin += currentWidget.mRight.mTarget.mOwner.mLeft.getMargin();
                                    }
                                }
                                system.addGreaterThan(currentWidget.mRight.mSolverVariable, currentWidget.mLeft.mSolverVariable, 0, 1);
                                system.addLowerThan(currentWidget.mRight.mSolverVariable, currentWidget.mRight.mTarget.mSolverVariable, -margin, 1);
                            }
                            previous = currentWidget;
                            currentWidget = currentWidget.mHorizontalNextWidget;
                        }
                        if (numMatchConstraints == 1) {
                            ConstraintWidget w = this.mMatchConstraintsChainedWidgets[0];
                            leftMargin = w.mLeft.getMargin();
                            if (w.mLeft.mTarget != null) {
                                leftMargin += w.mLeft.mTarget.getMargin();
                            }
                            rightMargin = w.mRight.getMargin();
                            if (w.mRight.mTarget != null) {
                                rightMargin += w.mRight.mTarget.getMargin();
                            }
                            rightTarget = widget.mRight.mTarget.mSolverVariable;
                            if (w == this.mChainEnds[3]) {
                                rightTarget = this.mChainEnds[1].mRight.mTarget.mSolverVariable;
                            }
                            if (w.mMatchConstraintDefaultWidth == 1) {
                                system.addGreaterThan(widget.mLeft.mSolverVariable, widget.mLeft.mTarget.mSolverVariable, leftMargin, 1);
                                system.addLowerThan(widget.mRight.mSolverVariable, rightTarget, -rightMargin, 1);
                                system.addEquality(widget.mRight.mSolverVariable, widget.mLeft.mSolverVariable, widget.getWidth(), 2);
                            } else {
                                system.addEquality(w.mLeft.mSolverVariable, w.mLeft.mTarget.mSolverVariable, leftMargin, 1);
                                system.addEquality(w.mRight.mSolverVariable, rightTarget, -rightMargin, 1);
                            }
                        } else {
                            for (int j = 0; j < numMatchConstraints - 1; j++) {
                                ConstraintWidget current = this.mMatchConstraintsChainedWidgets[j];
                                ConstraintWidget nextWidget = this.mMatchConstraintsChainedWidgets[j + 1];
                                SolverVariable left2 = current.mLeft.mSolverVariable;
                                SolverVariable right2 = current.mRight.mSolverVariable;
                                SolverVariable nextLeft = nextWidget.mLeft.mSolverVariable;
                                SolverVariable nextRight = nextWidget.mRight.mSolverVariable;
                                if (nextWidget == this.mChainEnds[3]) {
                                    nextRight = this.mChainEnds[1].mRight.mSolverVariable;
                                }
                                margin = current.mLeft.getMargin();
                                if (!(current.mLeft.mTarget == null || current.mLeft.mTarget.mOwner.mRight.mTarget == null || current.mLeft.mTarget.mOwner.mRight.mTarget.mOwner != current)) {
                                    margin += current.mLeft.mTarget.mOwner.mRight.getMargin();
                                }
                                system.addGreaterThan(left2, current.mLeft.mTarget.mSolverVariable, margin, 2);
                                margin = current.mRight.getMargin();
                                if (!(current.mRight.mTarget == null || current.mHorizontalNextWidget == null)) {
                                    margin += current.mHorizontalNextWidget.mLeft.mTarget != null ? current.mHorizontalNextWidget.mLeft.getMargin() : 0;
                                }
                                system.addLowerThan(right2, current.mRight.mTarget.mSolverVariable, -margin, 2);
                                if (j + 1 == numMatchConstraints - 1) {
                                    margin = nextWidget.mLeft.getMargin();
                                    if (!(nextWidget.mLeft.mTarget == null || nextWidget.mLeft.mTarget.mOwner.mRight.mTarget == null || nextWidget.mLeft.mTarget.mOwner.mRight.mTarget.mOwner != nextWidget)) {
                                        margin += nextWidget.mLeft.mTarget.mOwner.mRight.getMargin();
                                    }
                                    system.addGreaterThan(nextLeft, nextWidget.mLeft.mTarget.mSolverVariable, margin, 2);
                                    ConstraintAnchor anchor = nextWidget.mRight;
                                    if (nextWidget == this.mChainEnds[3]) {
                                        anchor = this.mChainEnds[1].mRight;
                                    }
                                    margin = anchor.getMargin();
                                    if (!(anchor.mTarget == null || anchor.mTarget.mOwner.mLeft.mTarget == null || anchor.mTarget.mOwner.mLeft.mTarget.mOwner != nextWidget)) {
                                        margin += anchor.mTarget.mOwner.mLeft.getMargin();
                                    }
                                    system.addLowerThan(nextRight, anchor.mTarget.mSolverVariable, -margin, 2);
                                }
                                if (widget.mMatchConstraintMaxWidth > 0) {
                                    system.addLowerThan(right2, left2, widget.mMatchConstraintMaxWidth, 2);
                                }
                                ArrayRow row = system.createRow();
                                row.createRowEqualDimension(current.mHorizontalWeight, totalWeights, nextWidget.mHorizontalWeight, left2, current.mLeft.getMargin(), right2, current.mRight.getMargin(), nextLeft, nextWidget.mLeft.getMargin(), nextRight, nextWidget.mRight.getMargin());
                                system.addConstraint(row);
                            }
                        }
                    }
                }
            }
        }
    }

    private void applyVerticalChain(LinearSystem system) {
        for (int i = 0; i < this.mVerticalChainsSize; i++) {
            ConstraintWidget first = this.mVerticalChainsArray[i];
            int numMatchConstraints = countMatchConstraintsChainedWidgets(system, this.mChainEnds, this.mVerticalChainsArray[i], 1, this.flags);
            ConstraintWidget currentWidget = this.mChainEnds[2];
            if (currentWidget != null) {
                if (this.flags[1]) {
                    int y = first.getDrawY();
                    while (currentWidget != null) {
                        system.addEquality(currentWidget.mTop.mSolverVariable, y);
                        y += (currentWidget.mTop.getMargin() + currentWidget.getHeight()) + currentWidget.mBottom.getMargin();
                        currentWidget = currentWidget.mVerticalNextWidget;
                    }
                } else {
                    boolean isChainSpread = first.mVerticalChainStyle == 0 ? USE_SNAPSHOT : false;
                    boolean isChainPacked = first.mVerticalChainStyle == 2 ? USE_SNAPSHOT : false;
                    ConstraintWidget widget = first;
                    boolean isWrapContent = this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT ? USE_SNAPSHOT : false;
                    if ((this.mOptimizationLevel == 2 || this.mOptimizationLevel == 8) && this.flags[0] && widget.mVerticalChainFixedPosition && !isChainPacked && !isWrapContent && first.mVerticalChainStyle == 0) {
                        Optimizer.applyDirectResolutionVerticalChain(this, system, numMatchConstraints, widget);
                    } else if (numMatchConstraints == 0 || isChainPacked) {
                        ConstraintAnchor top;
                        ConstraintAnchor bottom;
                        SolverVariable topTarget;
                        ConstraintWidget previousVisibleWidget = null;
                        ConstraintWidget lastWidget = null;
                        ConstraintWidget firstVisibleWidget = currentWidget;
                        boolean isLast = false;
                        while (currentWidget != null) {
                            ConstraintWidget next = currentWidget.mVerticalNextWidget;
                            if (next == null) {
                                lastWidget = this.mChainEnds[1];
                                isLast = USE_SNAPSHOT;
                            }
                            if (isChainPacked) {
                                top = currentWidget.mTop;
                                margin = top.getMargin();
                                if (previousVisibleWidget != null) {
                                    margin += previousVisibleWidget.mBottom.getMargin();
                                }
                                strength = 1;
                                if (firstVisibleWidget != currentWidget) {
                                    strength = 3;
                                }
                                SolverVariable source = null;
                                SolverVariable target = null;
                                if (top.mTarget != null) {
                                    source = top.mSolverVariable;
                                    target = top.mTarget.mSolverVariable;
                                } else if (currentWidget.mBaseline.mTarget != null) {
                                    source = currentWidget.mBaseline.mSolverVariable;
                                    target = currentWidget.mBaseline.mTarget.mSolverVariable;
                                    margin -= top.getMargin();
                                }
                                if (!(source == null || target == null)) {
                                    system.addGreaterThan(source, target, margin, strength);
                                }
                                if (currentWidget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    bottom = currentWidget.mBottom;
                                    if (currentWidget.mMatchConstraintDefaultHeight == 1) {
                                        system.addEquality(bottom.mSolverVariable, top.mSolverVariable, Math.max(currentWidget.mMatchConstraintMinHeight, currentWidget.getHeight()), 3);
                                    } else {
                                        system.addGreaterThan(top.mSolverVariable, top.mTarget.mSolverVariable, top.mMargin, 3);
                                        system.addLowerThan(bottom.mSolverVariable, top.mSolverVariable, currentWidget.mMatchConstraintMinHeight, 3);
                                    }
                                }
                            } else if (isChainSpread || !isLast || previousVisibleWidget == null) {
                                if (isChainSpread || isLast || previousVisibleWidget != null) {
                                    top = currentWidget.mTop;
                                    bottom = currentWidget.mBottom;
                                    topMargin = top.getMargin();
                                    bottomMargin = bottom.getMargin();
                                    system.addGreaterThan(top.mSolverVariable, top.mTarget.mSolverVariable, topMargin, 1);
                                    system.addLowerThan(bottom.mSolverVariable, bottom.mTarget.mSolverVariable, -bottomMargin, 1);
                                    topTarget = top.mTarget != null ? top.mTarget.mSolverVariable : null;
                                    if (previousVisibleWidget == null) {
                                        topTarget = first.mTop.mTarget != null ? first.mTop.mTarget.mSolverVariable : null;
                                    }
                                    if (next == null) {
                                        next = lastWidget.mBottom.mTarget != null ? lastWidget.mBottom.mTarget.mOwner : null;
                                    }
                                    if (next != null) {
                                        bottomTarget = next.mTop.mSolverVariable;
                                        if (isLast) {
                                            bottomTarget = lastWidget.mBottom.mTarget != null ? lastWidget.mBottom.mTarget.mSolverVariable : null;
                                        }
                                        if (!(topTarget == null || bottomTarget == null)) {
                                            system.addCentering(top.mSolverVariable, topTarget, topMargin, 0.5f, bottomTarget, bottom.mSolverVariable, bottomMargin, 4);
                                        }
                                    }
                                } else if (currentWidget.mTop.mTarget == null) {
                                    system.addEquality(currentWidget.mTop.mSolverVariable, currentWidget.getDrawY());
                                } else {
                                    system.addEquality(currentWidget.mTop.mSolverVariable, first.mTop.mTarget.mSolverVariable, currentWidget.mTop.getMargin(), 5);
                                }
                            } else if (currentWidget.mBottom.mTarget == null) {
                                system.addEquality(currentWidget.mBottom.mSolverVariable, currentWidget.getDrawBottom());
                            } else {
                                system.addEquality(currentWidget.mBottom.mSolverVariable, lastWidget.mBottom.mTarget.mSolverVariable, -currentWidget.mBottom.getMargin(), 5);
                            }
                            previousVisibleWidget = currentWidget;
                            if (isLast) {
                                currentWidget = null;
                            } else {
                                currentWidget = next;
                            }
                        }
                        if (isChainPacked) {
                            top = firstVisibleWidget.mTop;
                            bottom = lastWidget.mBottom;
                            topMargin = top.getMargin();
                            bottomMargin = bottom.getMargin();
                            topTarget = first.mTop.mTarget != null ? first.mTop.mTarget.mSolverVariable : null;
                            bottomTarget = lastWidget.mBottom.mTarget != null ? lastWidget.mBottom.mTarget.mSolverVariable : null;
                            if (!(topTarget == null || bottomTarget == null)) {
                                system.addLowerThan(bottom.mSolverVariable, bottomTarget, -bottomMargin, 1);
                                system.addCentering(top.mSolverVariable, topTarget, topMargin, first.mVerticalBiasPercent, bottomTarget, bottom.mSolverVariable, bottomMargin, 4);
                            }
                        }
                    } else {
                        ConstraintWidget previous = null;
                        float totalWeights = 0.0f;
                        while (currentWidget != null) {
                            if (currentWidget.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
                                margin = currentWidget.mTop.getMargin();
                                if (previous != null) {
                                    margin += previous.mBottom.getMargin();
                                }
                                strength = 3;
                                if (currentWidget.mTop.mTarget.mOwner.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    strength = 2;
                                }
                                system.addGreaterThan(currentWidget.mTop.mSolverVariable, currentWidget.mTop.mTarget.mSolverVariable, margin, strength);
                                margin = currentWidget.mBottom.getMargin();
                                if (currentWidget.mBottom.mTarget.mOwner.mTop.mTarget != null && currentWidget.mBottom.mTarget.mOwner.mTop.mTarget.mOwner == currentWidget) {
                                    margin += currentWidget.mBottom.mTarget.mOwner.mTop.getMargin();
                                }
                                strength = 3;
                                if (currentWidget.mBottom.mTarget.mOwner.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                                    strength = 2;
                                }
                                system.addLowerThan(currentWidget.mBottom.mSolverVariable, currentWidget.mBottom.mTarget.mSolverVariable, -margin, strength);
                            } else {
                                totalWeights += currentWidget.mVerticalWeight;
                                margin = 0;
                                if (currentWidget.mBottom.mTarget != null) {
                                    margin = currentWidget.mBottom.getMargin();
                                    if (currentWidget != this.mChainEnds[3]) {
                                        margin += currentWidget.mBottom.mTarget.mOwner.mTop.getMargin();
                                    }
                                }
                                system.addGreaterThan(currentWidget.mBottom.mSolverVariable, currentWidget.mTop.mSolverVariable, 0, 1);
                                system.addLowerThan(currentWidget.mBottom.mSolverVariable, currentWidget.mBottom.mTarget.mSolverVariable, -margin, 1);
                            }
                            previous = currentWidget;
                            currentWidget = currentWidget.mVerticalNextWidget;
                        }
                        if (numMatchConstraints == 1) {
                            ConstraintWidget w = this.mMatchConstraintsChainedWidgets[0];
                            topMargin = w.mTop.getMargin();
                            if (w.mTop.mTarget != null) {
                                topMargin += w.mTop.mTarget.getMargin();
                            }
                            bottomMargin = w.mBottom.getMargin();
                            if (w.mBottom.mTarget != null) {
                                bottomMargin += w.mBottom.mTarget.getMargin();
                            }
                            bottomTarget = widget.mBottom.mTarget.mSolverVariable;
                            if (w == this.mChainEnds[3]) {
                                bottomTarget = this.mChainEnds[1].mBottom.mTarget.mSolverVariable;
                            }
                            if (w.mMatchConstraintDefaultHeight == 1) {
                                system.addGreaterThan(widget.mTop.mSolverVariable, widget.mTop.mTarget.mSolverVariable, topMargin, 1);
                                system.addLowerThan(widget.mBottom.mSolverVariable, bottomTarget, -bottomMargin, 1);
                                system.addEquality(widget.mBottom.mSolverVariable, widget.mTop.mSolverVariable, widget.getHeight(), 2);
                            } else {
                                system.addEquality(w.mTop.mSolverVariable, w.mTop.mTarget.mSolverVariable, topMargin, 1);
                                system.addEquality(w.mBottom.mSolverVariable, bottomTarget, -bottomMargin, 1);
                            }
                        } else {
                            for (int j = 0; j < numMatchConstraints - 1; j++) {
                                ConstraintWidget current = this.mMatchConstraintsChainedWidgets[j];
                                ConstraintWidget nextWidget = this.mMatchConstraintsChainedWidgets[j + 1];
                                SolverVariable top2 = current.mTop.mSolverVariable;
                                SolverVariable bottom2 = current.mBottom.mSolverVariable;
                                SolverVariable nextTop = nextWidget.mTop.mSolverVariable;
                                SolverVariable nextBottom = nextWidget.mBottom.mSolverVariable;
                                if (nextWidget == this.mChainEnds[3]) {
                                    nextBottom = this.mChainEnds[1].mBottom.mSolverVariable;
                                }
                                margin = current.mTop.getMargin();
                                if (!(current.mTop.mTarget == null || current.mTop.mTarget.mOwner.mBottom.mTarget == null || current.mTop.mTarget.mOwner.mBottom.mTarget.mOwner != current)) {
                                    margin += current.mTop.mTarget.mOwner.mBottom.getMargin();
                                }
                                system.addGreaterThan(top2, current.mTop.mTarget.mSolverVariable, margin, 2);
                                margin = current.mBottom.getMargin();
                                if (!(current.mBottom.mTarget == null || current.mVerticalNextWidget == null)) {
                                    margin += current.mVerticalNextWidget.mTop.mTarget != null ? current.mVerticalNextWidget.mTop.getMargin() : 0;
                                }
                                system.addLowerThan(bottom2, current.mBottom.mTarget.mSolverVariable, -margin, 2);
                                if (j + 1 == numMatchConstraints - 1) {
                                    margin = nextWidget.mTop.getMargin();
                                    if (!(nextWidget.mTop.mTarget == null || nextWidget.mTop.mTarget.mOwner.mBottom.mTarget == null || nextWidget.mTop.mTarget.mOwner.mBottom.mTarget.mOwner != nextWidget)) {
                                        margin += nextWidget.mTop.mTarget.mOwner.mBottom.getMargin();
                                    }
                                    system.addGreaterThan(nextTop, nextWidget.mTop.mTarget.mSolverVariable, margin, 2);
                                    ConstraintAnchor anchor = nextWidget.mBottom;
                                    if (nextWidget == this.mChainEnds[3]) {
                                        anchor = this.mChainEnds[1].mBottom;
                                    }
                                    margin = anchor.getMargin();
                                    if (!(anchor.mTarget == null || anchor.mTarget.mOwner.mTop.mTarget == null || anchor.mTarget.mOwner.mTop.mTarget.mOwner != nextWidget)) {
                                        margin += anchor.mTarget.mOwner.mTop.getMargin();
                                    }
                                    system.addLowerThan(nextBottom, anchor.mTarget.mSolverVariable, -margin, 2);
                                }
                                if (widget.mMatchConstraintMaxHeight > 0) {
                                    system.addLowerThan(bottom2, top2, widget.mMatchConstraintMaxHeight, 2);
                                }
                                ArrayRow row = system.createRow();
                                row.createRowEqualDimension(current.mVerticalWeight, totalWeights, nextWidget.mVerticalWeight, top2, current.mTop.getMargin(), bottom2, current.mBottom.getMargin(), nextTop, nextWidget.mTop.getMargin(), nextBottom, nextWidget.mBottom.getMargin());
                                system.addConstraint(row);
                            }
                        }
                    }
                }
            }
        }
    }

    public void updateChildrenFromSolver(LinearSystem system, int group, boolean[] flags) {
        flags[2] = false;
        updateFromSolver(system, group);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            widget.updateFromSolver(system, group);
            if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.getWidth() < widget.getWrapWidth()) {
                flags[2] = USE_SNAPSHOT;
            }
            if (widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.getHeight() < widget.getWrapHeight()) {
                flags[2] = USE_SNAPSHOT;
            }
        }
    }

    public void setPadding(int left, int top, int right, int bottom) {
        this.mPaddingLeft = left;
        this.mPaddingTop = top;
        this.mPaddingRight = right;
        this.mPaddingBottom = bottom;
    }

    public void layout() {
        int i;
        int prex = this.mX;
        int prey = this.mY;
        int prew = Math.max(0, getWidth());
        int preh = Math.max(0, getHeight());
        this.mWidthMeasuredTooSmall = false;
        this.mHeightMeasuredTooSmall = false;
        if (this.mParent != null) {
            if (this.mSnapshot == null) {
                this.mSnapshot = new Snapshot(this);
            }
            this.mSnapshot.updateFrom(this);
            setX(this.mPaddingLeft);
            setY(this.mPaddingTop);
            resetAnchors();
            resetSolverVariables(this.mSystem.getCache());
        } else {
            this.mX = 0;
            this.mY = 0;
        }
        boolean wrap_override = false;
        DimensionBehaviour originalVerticalDimensionBehaviour = this.mVerticalDimensionBehaviour;
        DimensionBehaviour originalHorizontalDimensionBehaviour = this.mHorizontalDimensionBehaviour;
        if (this.mOptimizationLevel == 2 && (this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT || this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT)) {
            findWrapSize(this.mChildren, this.flags);
            wrap_override = this.flags[0];
            if (prew > 0 && preh > 0 && (this.mWrapWidth > prew || this.mWrapHeight > preh)) {
                wrap_override = false;
            }
            if (wrap_override) {
                if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
                    if (prew <= 0 || prew >= this.mWrapWidth) {
                        setWidth(Math.max(this.mMinWidth, this.mWrapWidth));
                    } else {
                        this.mWidthMeasuredTooSmall = USE_SNAPSHOT;
                        setWidth(prew);
                    }
                }
                if (this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
                    if (preh <= 0 || preh >= this.mWrapHeight) {
                        setHeight(Math.max(this.mMinHeight, this.mWrapHeight));
                    } else {
                        this.mHeightMeasuredTooSmall = USE_SNAPSHOT;
                        setHeight(preh);
                    }
                }
            }
        }
        resetChains();
        int count = this.mChildren.size();
        for (i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof WidgetContainer) {
                ((WidgetContainer) widget).layout();
            }
        }
        boolean needsSolving = USE_SNAPSHOT;
        int countSolve = 0;
        while (needsSolving) {
            countSolve++;
            try {
                this.mSystem.reset();
                needsSolving = addChildrenToSolver(this.mSystem, ConstraintAnchor.ANY_GROUP);
                if (needsSolving) {
                    this.mSystem.minimize();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (!needsSolving) {
                updateFromSolver(this.mSystem, ConstraintAnchor.ANY_GROUP);
                for (i = 0; i < count; i++) {
                    widget = (ConstraintWidget) this.mChildren.get(i);
                    if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.getWidth() < widget.getWrapWidth()) {
                        this.flags[2] = USE_SNAPSHOT;
                        break;
                    }
                    if (widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.getHeight() < widget.getWrapHeight()) {
                        this.flags[2] = USE_SNAPSHOT;
                        break;
                    }
                }
            } else {
                updateChildrenFromSolver(this.mSystem, ConstraintAnchor.ANY_GROUP, this.flags);
            }
            needsSolving = false;
            if (countSolve < 8 && this.flags[2]) {
                int maxX = 0;
                int maxY = 0;
                for (i = 0; i < count; i++) {
                    widget = (ConstraintWidget) this.mChildren.get(i);
                    maxX = Math.max(maxX, widget.mX + widget.getWidth());
                    maxY = Math.max(maxY, widget.mY + widget.getHeight());
                }
                maxX = Math.max(this.mMinWidth, maxX);
                maxY = Math.max(this.mMinHeight, maxY);
                if (originalHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && getWidth() < maxX) {
                    setWidth(maxX);
                    this.mHorizontalDimensionBehaviour = DimensionBehaviour.WRAP_CONTENT;
                    wrap_override = USE_SNAPSHOT;
                    needsSolving = USE_SNAPSHOT;
                }
                if (originalVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && getHeight() < maxY) {
                    setHeight(maxY);
                    this.mVerticalDimensionBehaviour = DimensionBehaviour.WRAP_CONTENT;
                    wrap_override = USE_SNAPSHOT;
                    needsSolving = USE_SNAPSHOT;
                }
            }
            int width = Math.max(this.mMinWidth, getWidth());
            if (width > getWidth()) {
                setWidth(width);
                this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
                wrap_override = USE_SNAPSHOT;
                needsSolving = USE_SNAPSHOT;
            }
            int height = Math.max(this.mMinHeight, getHeight());
            if (height > getHeight()) {
                setHeight(height);
                this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
                wrap_override = USE_SNAPSHOT;
                needsSolving = USE_SNAPSHOT;
            }
            if (!wrap_override) {
                if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && prew > 0 && getWidth() > prew) {
                    this.mWidthMeasuredTooSmall = USE_SNAPSHOT;
                    wrap_override = USE_SNAPSHOT;
                    this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
                    setWidth(prew);
                    needsSolving = USE_SNAPSHOT;
                }
                if (this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && preh > 0 && getHeight() > preh) {
                    this.mHeightMeasuredTooSmall = USE_SNAPSHOT;
                    wrap_override = USE_SNAPSHOT;
                    this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
                    setHeight(preh);
                    needsSolving = USE_SNAPSHOT;
                }
            }
        }
        if (this.mParent != null) {
            width = Math.max(this.mMinWidth, getWidth());
            height = Math.max(this.mMinHeight, getHeight());
            this.mSnapshot.applyTo(this);
            setWidth((this.mPaddingLeft + width) + this.mPaddingRight);
            setHeight((this.mPaddingTop + height) + this.mPaddingBottom);
        } else {
            this.mX = prex;
            this.mY = prey;
        }
        if (wrap_override) {
            this.mHorizontalDimensionBehaviour = originalHorizontalDimensionBehaviour;
            this.mVerticalDimensionBehaviour = originalVerticalDimensionBehaviour;
        }
        resetSolverVariables(this.mSystem.getCache());
        if (this == getRootConstraintContainer()) {
            updateDrawPosition();
        }
    }

    static int setGroup(ConstraintAnchor anchor, int group) {
        int oldGroup = anchor.mGroup;
        if (anchor.mOwner.getParent() == null) {
            return group;
        }
        if (oldGroup <= group) {
            return oldGroup;
        }
        anchor.mGroup = group;
        ConstraintAnchor opposite = anchor.getOpposite();
        ConstraintAnchor target = anchor.mTarget;
        if (opposite != null) {
            group = setGroup(opposite, group);
        }
        if (target != null) {
            group = setGroup(target, group);
        }
        if (opposite != null) {
            group = setGroup(opposite, group);
        }
        anchor.mGroup = group;
        return group;
    }

    public int layoutFindGroupsSimple() {
        int size = this.mChildren.size();
        for (int j = 0; j < size; j++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(j);
            widget.mLeft.mGroup = 0;
            widget.mRight.mGroup = 0;
            widget.mTop.mGroup = 1;
            widget.mBottom.mGroup = 1;
            widget.mBaseline.mGroup = 1;
        }
        return 2;
    }

    public void findHorizontalWrapRecursive(ConstraintWidget widget, boolean[] flags) {
        boolean z = false;
        if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && widget.mDimensionRatio > 0.0f) {
            flags[0] = false;
            return;
        }
        int w = widget.getOptimizerWrapWidth();
        if (widget.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT || widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT || widget.mDimensionRatio <= 0.0f) {
            int distToRight = w;
            int distToLeft = w;
            ConstraintWidget leftWidget = null;
            ConstraintWidget rightWidget = null;
            widget.mHorizontalWrapVisited = USE_SNAPSHOT;
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 1) {
                    distToLeft = 0;
                    distToRight = 0;
                    if (guideline.getRelativeBegin() != -1) {
                        distToLeft = guideline.getRelativeBegin();
                    } else if (guideline.getRelativeEnd() != -1) {
                        distToRight = guideline.getRelativeEnd();
                    }
                }
            } else if (!widget.mRight.isConnected() && !widget.mLeft.isConnected()) {
                distToLeft += widget.getX();
            } else if (widget.mRight.mTarget == null || widget.mLeft.mTarget == null || (widget.mRight.mTarget != widget.mLeft.mTarget && (widget.mRight.mTarget.mOwner != widget.mLeft.mTarget.mOwner || widget.mRight.mTarget.mOwner == widget.mParent))) {
                if (widget.mRight.mTarget != null) {
                    rightWidget = widget.mRight.mTarget.mOwner;
                    distToRight += widget.mRight.getMargin();
                    if (!(rightWidget.isRoot() || rightWidget.mHorizontalWrapVisited)) {
                        findHorizontalWrapRecursive(rightWidget, flags);
                    }
                }
                if (widget.mLeft.mTarget != null) {
                    leftWidget = widget.mLeft.mTarget.mOwner;
                    distToLeft += widget.mLeft.getMargin();
                    if (!(leftWidget.isRoot() || leftWidget.mHorizontalWrapVisited)) {
                        findHorizontalWrapRecursive(leftWidget, flags);
                    }
                }
                if (!(widget.mRight.mTarget == null || rightWidget.isRoot())) {
                    if (widget.mRight.mTarget.mType == Type.RIGHT) {
                        distToRight += rightWidget.mDistToRight - rightWidget.getOptimizerWrapWidth();
                    } else if (widget.mRight.mTarget.getType() == Type.LEFT) {
                        distToRight += rightWidget.mDistToRight;
                    }
                    boolean z2 = (rightWidget.mRightHasCentered || !(rightWidget.mLeft.mTarget == null || rightWidget.mRight.mTarget == null || rightWidget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT)) ? USE_SNAPSHOT : false;
                    widget.mRightHasCentered = z2;
                    if (widget.mRightHasCentered) {
                        if (rightWidget.mLeft.mTarget != null) {
                            if (rightWidget.mLeft.mTarget.mOwner != widget) {
                            }
                        }
                        distToRight += distToRight - rightWidget.mDistToRight;
                    }
                }
                if (!(widget.mLeft.mTarget == null || leftWidget.isRoot())) {
                    if (widget.mLeft.mTarget.getType() == Type.LEFT) {
                        distToLeft += leftWidget.mDistToLeft - leftWidget.getOptimizerWrapWidth();
                    } else if (widget.mLeft.mTarget.getType() == Type.RIGHT) {
                        distToLeft += leftWidget.mDistToLeft;
                    }
                    if (leftWidget.mLeftHasCentered || !(leftWidget.mLeft.mTarget == null || leftWidget.mRight.mTarget == null || leftWidget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT)) {
                        z = USE_SNAPSHOT;
                    }
                    widget.mLeftHasCentered = z;
                    if (widget.mLeftHasCentered) {
                        if (leftWidget.mRight.mTarget != null) {
                            if (leftWidget.mRight.mTarget.mOwner != widget) {
                            }
                        }
                        distToLeft += distToLeft - leftWidget.mDistToLeft;
                    }
                }
            } else {
                flags[0] = false;
                return;
            }
            if (widget.getVisibility() == 8) {
                distToLeft -= widget.mWidth;
                distToRight -= widget.mWidth;
            }
            widget.mDistToLeft = distToLeft;
            widget.mDistToRight = distToRight;
            return;
        }
        flags[0] = false;
    }

    public void findVerticalWrapRecursive(ConstraintWidget widget, boolean[] flags) {
        boolean z = false;
        if (widget.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT || widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT || widget.mDimensionRatio <= 0.0f) {
            int h = widget.getOptimizerWrapHeight();
            int distToTop = h;
            int distToBottom = h;
            ConstraintWidget topWidget = null;
            ConstraintWidget bottomWidget = null;
            widget.mVerticalWrapVisited = USE_SNAPSHOT;
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 0) {
                    distToTop = 0;
                    distToBottom = 0;
                    if (guideline.getRelativeBegin() != -1) {
                        distToTop = guideline.getRelativeBegin();
                    } else if (guideline.getRelativeEnd() != -1) {
                        distToBottom = guideline.getRelativeEnd();
                    }
                }
            } else if (widget.mBaseline.mTarget == null && widget.mTop.mTarget == null && widget.mBottom.mTarget == null) {
                distToTop += widget.getY();
            } else if (widget.mBottom.mTarget != null && widget.mTop.mTarget != null && (widget.mBottom.mTarget == widget.mTop.mTarget || (widget.mBottom.mTarget.mOwner == widget.mTop.mTarget.mOwner && widget.mBottom.mTarget.mOwner != widget.mParent))) {
                flags[0] = false;
                return;
            } else if (widget.mBaseline.isConnected()) {
                ConstraintWidget baseLineWidget = widget.mBaseline.mTarget.getOwner();
                if (!baseLineWidget.mVerticalWrapVisited) {
                    findVerticalWrapRecursive(baseLineWidget, flags);
                }
                distToTop = Math.max((baseLineWidget.mDistToTop - baseLineWidget.mHeight) + h, h);
                distToBottom = Math.max((baseLineWidget.mDistToBottom - baseLineWidget.mHeight) + h, h);
                if (widget.getVisibility() == 8) {
                    distToTop -= widget.mHeight;
                    distToBottom -= widget.mHeight;
                }
                widget.mDistToTop = distToTop;
                widget.mDistToBottom = distToBottom;
                return;
            } else {
                if (widget.mTop.isConnected()) {
                    topWidget = widget.mTop.mTarget.getOwner();
                    distToTop += widget.mTop.getMargin();
                    if (!(topWidget.isRoot() || topWidget.mVerticalWrapVisited)) {
                        findVerticalWrapRecursive(topWidget, flags);
                    }
                }
                if (widget.mBottom.isConnected()) {
                    bottomWidget = widget.mBottom.mTarget.getOwner();
                    distToBottom += widget.mBottom.getMargin();
                    if (!(bottomWidget.isRoot() || bottomWidget.mVerticalWrapVisited)) {
                        findVerticalWrapRecursive(bottomWidget, flags);
                    }
                }
                if (!(widget.mTop.mTarget == null || topWidget.isRoot())) {
                    if (widget.mTop.mTarget.getType() == Type.TOP) {
                        distToTop += topWidget.mDistToTop - topWidget.getOptimizerWrapHeight();
                    } else if (widget.mTop.mTarget.getType() == Type.BOTTOM) {
                        distToTop += topWidget.mDistToTop;
                    }
                    boolean z2 = (topWidget.mTopHasCentered || !(topWidget.mTop.mTarget == null || topWidget.mTop.mTarget.mOwner == widget || topWidget.mBottom.mTarget == null || topWidget.mBottom.mTarget.mOwner == widget || topWidget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT)) ? USE_SNAPSHOT : false;
                    widget.mTopHasCentered = z2;
                    if (widget.mTopHasCentered) {
                        if (topWidget.mBottom.mTarget != null) {
                            if (topWidget.mBottom.mTarget.mOwner != widget) {
                            }
                        }
                        distToTop += distToTop - topWidget.mDistToTop;
                    }
                }
                if (!(widget.mBottom.mTarget == null || bottomWidget.isRoot())) {
                    if (widget.mBottom.mTarget.getType() == Type.BOTTOM) {
                        distToBottom += bottomWidget.mDistToBottom - bottomWidget.getOptimizerWrapHeight();
                    } else if (widget.mBottom.mTarget.getType() == Type.TOP) {
                        distToBottom += bottomWidget.mDistToBottom;
                    }
                    if (bottomWidget.mBottomHasCentered || !(bottomWidget.mTop.mTarget == null || bottomWidget.mTop.mTarget.mOwner == widget || bottomWidget.mBottom.mTarget == null || bottomWidget.mBottom.mTarget.mOwner == widget || bottomWidget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT)) {
                        z = USE_SNAPSHOT;
                    }
                    widget.mBottomHasCentered = z;
                    if (widget.mBottomHasCentered) {
                        if (bottomWidget.mTop.mTarget != null) {
                            if (bottomWidget.mTop.mTarget.mOwner != widget) {
                            }
                        }
                        distToBottom += distToBottom - bottomWidget.mDistToBottom;
                    }
                }
            }
            if (widget.getVisibility() == 8) {
                distToTop -= widget.mHeight;
                distToBottom -= widget.mHeight;
            }
            widget.mDistToTop = distToTop;
            widget.mDistToBottom = distToBottom;
            return;
        }
        flags[0] = false;
    }

    public void findWrapSize(ArrayList<ConstraintWidget> children, boolean[] flags) {
        int j;
        int maxTopDist = 0;
        int maxLeftDist = 0;
        int maxRightDist = 0;
        int maxBottomDist = 0;
        int maxConnectWidth = 0;
        int maxConnectHeight = 0;
        int size = children.size();
        flags[0] = USE_SNAPSHOT;
        for (j = 0; j < size; j++) {
            ConstraintWidget widget = (ConstraintWidget) children.get(j);
            if (!widget.isRoot()) {
                if (!widget.mHorizontalWrapVisited) {
                    findHorizontalWrapRecursive(widget, flags);
                }
                if (!widget.mVerticalWrapVisited) {
                    findVerticalWrapRecursive(widget, flags);
                }
                if (flags[0]) {
                    int connectWidth = (widget.mDistToLeft + widget.mDistToRight) - widget.getWidth();
                    int connectHeight = (widget.mDistToTop + widget.mDistToBottom) - widget.getHeight();
                    if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
                        connectWidth = (widget.getWidth() + widget.mLeft.mMargin) + widget.mRight.mMargin;
                    }
                    if (widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_PARENT) {
                        connectHeight = (widget.getHeight() + widget.mTop.mMargin) + widget.mBottom.mMargin;
                    }
                    if (widget.getVisibility() == 8) {
                        connectWidth = 0;
                        connectHeight = 0;
                    }
                    maxLeftDist = Math.max(maxLeftDist, widget.mDistToLeft);
                    maxRightDist = Math.max(maxRightDist, widget.mDistToRight);
                    maxBottomDist = Math.max(maxBottomDist, widget.mDistToBottom);
                    maxTopDist = Math.max(maxTopDist, widget.mDistToTop);
                    maxConnectWidth = Math.max(maxConnectWidth, connectWidth);
                    maxConnectHeight = Math.max(maxConnectHeight, connectHeight);
                } else {
                    return;
                }
            }
        }
        this.mWrapWidth = Math.max(this.mMinWidth, Math.max(Math.max(maxLeftDist, maxRightDist), maxConnectWidth));
        this.mWrapHeight = Math.max(this.mMinHeight, Math.max(Math.max(maxTopDist, maxBottomDist), maxConnectHeight));
        for (j = 0; j < size; j++) {
            ConstraintWidget child = (ConstraintWidget) children.get(j);
            child.mHorizontalWrapVisited = false;
            child.mVerticalWrapVisited = false;
            child.mLeftHasCentered = false;
            child.mRightHasCentered = false;
            child.mTopHasCentered = false;
            child.mBottomHasCentered = false;
        }
    }

    public int layoutFindGroups() {
        int j;
        Type[] dir = new Type[]{Type.LEFT, Type.RIGHT, Type.TOP, Type.BASELINE, Type.BOTTOM};
        int label = 1;
        int size = this.mChildren.size();
        for (j = 0; j < size; j++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(j);
            ConstraintAnchor anchor = widget.mLeft;
            if (anchor.mTarget == null) {
                anchor.mGroup = ConstraintAnchor.ANY_GROUP;
            } else if (setGroup(anchor, label) == label) {
                label++;
            }
            anchor = widget.mTop;
            if (anchor.mTarget == null) {
                anchor.mGroup = ConstraintAnchor.ANY_GROUP;
            } else if (setGroup(anchor, label) == label) {
                label++;
            }
            anchor = widget.mRight;
            if (anchor.mTarget == null) {
                anchor.mGroup = ConstraintAnchor.ANY_GROUP;
            } else if (setGroup(anchor, label) == label) {
                label++;
            }
            anchor = widget.mBottom;
            if (anchor.mTarget == null) {
                anchor.mGroup = ConstraintAnchor.ANY_GROUP;
            } else if (setGroup(anchor, label) == label) {
                label++;
            }
            anchor = widget.mBaseline;
            if (anchor.mTarget == null) {
                anchor.mGroup = ConstraintAnchor.ANY_GROUP;
            } else if (setGroup(anchor, label) == label) {
                label++;
            }
        }
        boolean notDone = USE_SNAPSHOT;
        int count = 0;
        int fix = 0;
        while (notDone) {
            notDone = false;
            count++;
            for (j = 0; j < size; j++) {
                widget = (ConstraintWidget) this.mChildren.get(j);
                for (Type type : dir) {
                    anchor = null;
                    switch (type) {
                        case LEFT:
                            anchor = widget.mLeft;
                            break;
                        case TOP:
                            anchor = widget.mTop;
                            break;
                        case RIGHT:
                            anchor = widget.mRight;
                            break;
                        case BOTTOM:
                            anchor = widget.mBottom;
                            break;
                        case BASELINE:
                            anchor = widget.mBaseline;
                            break;
                    }
                    ConstraintAnchor target = anchor.mTarget;
                    if (target != null) {
                        int i;
                        if (!(target.mOwner.getParent() == null || target.mGroup == anchor.mGroup)) {
                            i = anchor.mGroup > target.mGroup ? target.mGroup : anchor.mGroup;
                            anchor.mGroup = i;
                            target.mGroup = i;
                            fix++;
                            notDone = USE_SNAPSHOT;
                        }
                        ConstraintAnchor opposite = target.getOpposite();
                        if (!(opposite == null || opposite.mGroup == anchor.mGroup)) {
                            i = anchor.mGroup > opposite.mGroup ? opposite.mGroup : anchor.mGroup;
                            anchor.mGroup = i;
                            opposite.mGroup = i;
                            fix++;
                            notDone = USE_SNAPSHOT;
                        }
                    }
                }
            }
        }
        int[] table = new int[((this.mChildren.size() * dir.length) + 1)];
        Arrays.fill(table, -1);
        j = 0;
        int index = 0;
        while (j < size) {
            int i2;
            widget = (ConstraintWidget) this.mChildren.get(j);
            anchor = widget.mLeft;
            if (anchor.mGroup != Integer.MAX_VALUE) {
                int g;
                g = anchor.mGroup;
                if (table[g] == -1) {
                    i2 = index + 1;
                    table[g] = index;
                } else {
                    i2 = index;
                }
                anchor.mGroup = table[g];
            } else {
                i2 = index;
            }
            anchor = widget.mTop;
            if (anchor.mGroup != Integer.MAX_VALUE) {
                g = anchor.mGroup;
                if (table[g] == -1) {
                    index = i2 + 1;
                    table[g] = i2;
                    i2 = index;
                }
                anchor.mGroup = table[g];
            }
            anchor = widget.mRight;
            if (anchor.mGroup != Integer.MAX_VALUE) {
                g = anchor.mGroup;
                if (table[g] == -1) {
                    index = i2 + 1;
                    table[g] = i2;
                    i2 = index;
                }
                anchor.mGroup = table[g];
            }
            anchor = widget.mBottom;
            if (anchor.mGroup != Integer.MAX_VALUE) {
                g = anchor.mGroup;
                if (table[g] == -1) {
                    index = i2 + 1;
                    table[g] = i2;
                    i2 = index;
                }
                anchor.mGroup = table[g];
            }
            anchor = widget.mBaseline;
            if (anchor.mGroup != Integer.MAX_VALUE) {
                g = anchor.mGroup;
                if (table[g] == -1) {
                    index = i2 + 1;
                    table[g] = i2;
                    i2 = index;
                }
                anchor.mGroup = table[g];
            }
            j++;
            index = i2;
        }
        return index;
    }

    public void layoutWithGroup(int numOfGroups) {
        int i;
        int prex = this.mX;
        int prey = this.mY;
        if (this.mParent != null) {
            if (this.mSnapshot == null) {
                this.mSnapshot = new Snapshot(this);
            }
            this.mSnapshot.updateFrom(this);
            this.mX = 0;
            this.mY = 0;
            resetAnchors();
            resetSolverVariables(this.mSystem.getCache());
        } else {
            this.mX = 0;
            this.mY = 0;
        }
        int count = this.mChildren.size();
        for (i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof WidgetContainer) {
                ((WidgetContainer) widget).layout();
            }
        }
        this.mLeft.mGroup = 0;
        this.mRight.mGroup = 0;
        this.mTop.mGroup = 1;
        this.mBottom.mGroup = 1;
        this.mSystem.reset();
        for (i = 0; i < numOfGroups; i++) {
            try {
                addToSolver(this.mSystem, i);
                this.mSystem.minimize();
                updateFromSolver(this.mSystem, i);
            } catch (Exception e) {
                e.printStackTrace();
            }
            updateFromSolver(this.mSystem, -2);
        }
        if (this.mParent != null) {
            int width = getWidth();
            int height = getHeight();
            this.mSnapshot.applyTo(this);
            setWidth(width);
            setHeight(height);
        } else {
            this.mX = prex;
            this.mY = prey;
        }
        if (this == getRootConstraintContainer()) {
            updateDrawPosition();
        }
    }

    public boolean handlesInternalConstraints() {
        return false;
    }

    public ArrayList<Guideline> getVerticalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 1) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public ArrayList<Guideline> getHorizontalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 0) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public LinearSystem getSystem() {
        return this.mSystem;
    }

    private void resetChains() {
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
    }

    void addChain(ConstraintWidget constraintWidget, int type) {
        ConstraintWidget widget = constraintWidget;
        if (type == 0) {
            while (widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner.mRight.mTarget != null && widget.mLeft.mTarget.mOwner.mRight.mTarget == widget.mLeft && widget.mLeft.mTarget.mOwner != widget) {
                widget = widget.mLeft.mTarget.mOwner;
            }
            addHorizontalChain(widget);
        } else if (type == 1) {
            while (widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner.mBottom.mTarget != null && widget.mTop.mTarget.mOwner.mBottom.mTarget == widget.mTop && widget.mTop.mTarget.mOwner != widget) {
                widget = widget.mTop.mTarget.mOwner;
            }
            addVerticalChain(widget);
        }
    }

    private void addHorizontalChain(ConstraintWidget widget) {
        int i = 0;
        while (i < this.mHorizontalChainsSize) {
            if (this.mHorizontalChainsArray[i] != widget) {
                i++;
            } else {
                return;
            }
        }
        if (this.mHorizontalChainsSize + 1 >= this.mHorizontalChainsArray.length) {
            this.mHorizontalChainsArray = (ConstraintWidget[]) Arrays.copyOf(this.mHorizontalChainsArray, this.mHorizontalChainsArray.length * 2);
        }
        this.mHorizontalChainsArray[this.mHorizontalChainsSize] = widget;
        this.mHorizontalChainsSize++;
    }

    private void addVerticalChain(ConstraintWidget widget) {
        int i = 0;
        while (i < this.mVerticalChainsSize) {
            if (this.mVerticalChainsArray[i] != widget) {
                i++;
            } else {
                return;
            }
        }
        if (this.mVerticalChainsSize + 1 >= this.mVerticalChainsArray.length) {
            this.mVerticalChainsArray = (ConstraintWidget[]) Arrays.copyOf(this.mVerticalChainsArray, this.mVerticalChainsArray.length * 2);
        }
        this.mVerticalChainsArray[this.mVerticalChainsSize] = widget;
        this.mVerticalChainsSize++;
    }

    private int countMatchConstraintsChainedWidgets(LinearSystem system, ConstraintWidget[] chainEnds, ConstraintWidget widget, int direction, boolean[] flags) {
        int i = 0;
        flags[0] = USE_SNAPSHOT;
        flags[1] = false;
        chainEnds[0] = null;
        chainEnds[2] = null;
        chainEnds[1] = null;
        chainEnds[3] = null;
        boolean fixedPosition;
        ConstraintWidget first;
        ConstraintWidget last;
        ConstraintWidget firstVisible;
        ConstraintWidget lastVisible;
        int count;
        if (direction == 0) {
            fixedPosition = USE_SNAPSHOT;
            first = widget;
            last = null;
            if (!(widget.mLeft.mTarget == null || widget.mLeft.mTarget.mOwner == this)) {
                fixedPosition = false;
            }
            widget.mHorizontalNextWidget = null;
            firstVisible = null;
            if (widget.getVisibility() != 8) {
                firstVisible = widget;
            }
            lastVisible = firstVisible;
            while (widget.mRight.mTarget != null) {
                widget.mHorizontalNextWidget = null;
                if (widget.getVisibility() != 8) {
                    if (firstVisible == null) {
                        firstVisible = widget;
                    }
                    if (!(lastVisible == null || lastVisible == widget)) {
                        lastVisible.mHorizontalNextWidget = widget;
                    }
                    lastVisible = widget;
                } else {
                    system.addEquality(widget.mLeft.mSolverVariable, widget.mLeft.mTarget.mSolverVariable, 0, 5);
                    system.addEquality(widget.mRight.mSolverVariable, widget.mLeft.mSolverVariable, 0, 5);
                }
                if (widget.getVisibility() != 8 && widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                    if (widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                        flags[0] = false;
                    }
                    if (widget.mDimensionRatio <= 0.0f) {
                        flags[0] = false;
                        if (i + 1 >= this.mMatchConstraintsChainedWidgets.length) {
                            this.mMatchConstraintsChainedWidgets = (ConstraintWidget[]) Arrays.copyOf(this.mMatchConstraintsChainedWidgets, this.mMatchConstraintsChainedWidgets.length * 2);
                        }
                        count = i + 1;
                        this.mMatchConstraintsChainedWidgets[i] = widget;
                        i = count;
                    }
                }
                if (widget.mRight.mTarget.mOwner.mLeft.mTarget == null || widget.mRight.mTarget.mOwner.mLeft.mTarget.mOwner != widget || widget.mRight.mTarget.mOwner == widget) {
                    break;
                }
                widget = widget.mRight.mTarget.mOwner;
                last = widget;
            }
            if (!(widget.mRight.mTarget == null || widget.mRight.mTarget.mOwner == this)) {
                fixedPosition = false;
            }
            if (first.mLeft.mTarget == null || last.mRight.mTarget == null) {
                flags[1] = USE_SNAPSHOT;
            }
            first.mHorizontalChainFixedPosition = fixedPosition;
            last.mHorizontalNextWidget = null;
            chainEnds[0] = first;
            chainEnds[2] = firstVisible;
            chainEnds[1] = last;
            chainEnds[3] = lastVisible;
        } else {
            fixedPosition = USE_SNAPSHOT;
            first = widget;
            last = null;
            if (!(widget.mTop.mTarget == null || widget.mTop.mTarget.mOwner == this)) {
                fixedPosition = false;
            }
            widget.mVerticalNextWidget = null;
            firstVisible = null;
            if (widget.getVisibility() != 8) {
                firstVisible = widget;
            }
            lastVisible = firstVisible;
            while (widget.mBottom.mTarget != null) {
                widget.mVerticalNextWidget = null;
                if (widget.getVisibility() != 8) {
                    if (firstVisible == null) {
                        firstVisible = widget;
                    }
                    if (!(lastVisible == null || lastVisible == widget)) {
                        lastVisible.mVerticalNextWidget = widget;
                    }
                    lastVisible = widget;
                } else {
                    system.addEquality(widget.mTop.mSolverVariable, widget.mTop.mTarget.mSolverVariable, 0, 5);
                    system.addEquality(widget.mBottom.mSolverVariable, widget.mTop.mSolverVariable, 0, 5);
                }
                if (widget.getVisibility() != 8 && widget.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                    if (widget.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                        flags[0] = false;
                    }
                    if (widget.mDimensionRatio <= 0.0f) {
                        flags[0] = false;
                        if (i + 1 >= this.mMatchConstraintsChainedWidgets.length) {
                            this.mMatchConstraintsChainedWidgets = (ConstraintWidget[]) Arrays.copyOf(this.mMatchConstraintsChainedWidgets, this.mMatchConstraintsChainedWidgets.length * 2);
                        }
                        count = i + 1;
                        this.mMatchConstraintsChainedWidgets[i] = widget;
                        i = count;
                    }
                }
                if (widget.mBottom.mTarget.mOwner.mTop.mTarget == null || widget.mBottom.mTarget.mOwner.mTop.mTarget.mOwner != widget || widget.mBottom.mTarget.mOwner == widget) {
                    break;
                }
                widget = widget.mBottom.mTarget.mOwner;
                last = widget;
            }
            if (!(widget.mBottom.mTarget == null || widget.mBottom.mTarget.mOwner == this)) {
                fixedPosition = false;
            }
            if (first.mTop.mTarget == null || last.mBottom.mTarget == null) {
                flags[1] = USE_SNAPSHOT;
            }
            first.mVerticalChainFixedPosition = fixedPosition;
            last.mVerticalNextWidget = null;
            chainEnds[0] = first;
            chainEnds[2] = firstVisible;
            chainEnds[1] = last;
            chainEnds[3] = lastVisible;
        }
        return i;
    }
}
