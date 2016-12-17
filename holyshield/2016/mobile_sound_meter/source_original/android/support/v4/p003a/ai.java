package android.support.v4.p003a;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Animation.AnimationListener;

/* renamed from: android.support.v4.a.ai */
class ai implements AnimationListener {
    private AnimationListener f131a;
    private boolean f132b;
    private View f133c;

    public ai(View view, Animation animation) {
        this.f131a = null;
        this.f132b = false;
        this.f133c = null;
        if (view != null && animation != null) {
            this.f133c = view;
        }
    }

    public ai(View view, Animation animation, AnimationListener animationListener) {
        this.f131a = null;
        this.f132b = false;
        this.f133c = null;
        if (view != null && animation != null) {
            this.f131a = animationListener;
            this.f133c = view;
        }
    }

    public void onAnimationEnd(Animation animation) {
        if (this.f133c != null && this.f132b) {
            this.f133c.post(new ak(this));
        }
        if (this.f131a != null) {
            this.f131a.onAnimationEnd(animation);
        }
    }

    public void onAnimationRepeat(Animation animation) {
        if (this.f131a != null) {
            this.f131a.onAnimationRepeat(animation);
        }
    }

    public void onAnimationStart(Animation animation) {
        if (this.f133c != null) {
            this.f132b = af.m142a(this.f133c, animation);
            if (this.f132b) {
                this.f133c.post(new aj(this));
            }
        }
        if (this.f131a != null) {
            this.f131a.onAnimationStart(animation);
        }
    }
}
