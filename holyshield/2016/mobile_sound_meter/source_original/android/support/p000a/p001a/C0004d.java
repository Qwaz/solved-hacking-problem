package android.support.p000a.p001a;

import android.animation.Animator;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;
import android.graphics.drawable.Drawable.ConstantState;
import android.support.v4.p012g.C0107a;
import java.util.ArrayList;

/* renamed from: android.support.a.a.d */
class C0004d extends ConstantState {
    int f12a;
    C0011l f13b;
    ArrayList f14c;
    C0107a f15d;

    public C0004d(Context context, C0004d c0004d, Callback callback, Resources resources) {
        int i = 0;
        if (c0004d != null) {
            this.f12a = c0004d.f12a;
            if (c0004d.f13b != null) {
                ConstantState constantState = c0004d.f13b.getConstantState();
                if (resources != null) {
                    this.f13b = (C0011l) constantState.newDrawable(resources);
                } else {
                    this.f13b = (C0011l) constantState.newDrawable();
                }
                this.f13b = (C0011l) this.f13b.mutate();
                this.f13b.setCallback(callback);
                this.f13b.setBounds(c0004d.f13b.getBounds());
                this.f13b.m34a(false);
            }
            if (c0004d.f14c != null) {
                int size = c0004d.f14c.size();
                this.f14c = new ArrayList(size);
                this.f15d = new C0107a(size);
                while (i < size) {
                    Animator animator = (Animator) c0004d.f14c.get(i);
                    Animator clone = animator.clone();
                    String str = (String) c0004d.f15d.get(animator);
                    clone.setTarget(this.f13b.m33a(str));
                    this.f14c.add(clone);
                    this.f15d.put(clone, str);
                    i++;
                }
            }
        }
    }

    public int getChangingConfigurations() {
        return this.f12a;
    }

    public Drawable newDrawable() {
        throw new IllegalStateException("No constant state support for SDK < 23.");
    }

    public Drawable newDrawable(Resources resources) {
        throw new IllegalStateException("No constant state support for SDK < 23.");
    }
}
