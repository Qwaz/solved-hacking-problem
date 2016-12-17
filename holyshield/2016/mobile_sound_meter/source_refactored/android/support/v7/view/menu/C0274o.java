package android.support.v7.view.menu;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.C0161n;
import android.support.v4.p008d.p009a.C0090b;
import android.util.Log;
import android.view.ActionProvider;
import android.view.CollapsibleActionView;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.MenuItem;
import android.view.MenuItem.OnActionExpandListener;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.SubMenu;
import android.view.View;
import java.lang.reflect.Method;

@TargetApi(14)
/* renamed from: android.support.v7.view.menu.o */
public class C0274o extends C0263e implements MenuItem {
    private Method f1047c;

    C0274o(Context context, C0090b c0090b) {
        super(context, c0090b);
    }

    C0275p m2240a(ActionProvider actionProvider) {
        return new C0275p(this, this.a, actionProvider);
    }

    public void m2241a(boolean z) {
        try {
            if (this.f1047c == null) {
                this.f1047c = ((C0090b) this.b).getClass().getDeclaredMethod("setExclusiveCheckable", new Class[]{Boolean.TYPE});
            }
            this.f1047c.invoke(this.b, new Object[]{Boolean.valueOf(z)});
        } catch (Throwable e) {
            Log.w("MenuItemWrapper", "Error while calling setExclusiveCheckable", e);
        }
    }

    public boolean collapseActionView() {
        return ((C0090b) this.b).collapseActionView();
    }

    public boolean expandActionView() {
        return ((C0090b) this.b).expandActionView();
    }

    public ActionProvider getActionProvider() {
        C0161n a = ((C0090b) this.b).m571a();
        return a instanceof C0275p ? ((C0275p) a).f1048a : null;
    }

    public View getActionView() {
        View actionView = ((C0090b) this.b).getActionView();
        return actionView instanceof C0276q ? ((C0276q) actionView).m2248c() : actionView;
    }

    public char getAlphabeticShortcut() {
        return ((C0090b) this.b).getAlphabeticShortcut();
    }

    public int getGroupId() {
        return ((C0090b) this.b).getGroupId();
    }

    public Drawable getIcon() {
        return ((C0090b) this.b).getIcon();
    }

    public Intent getIntent() {
        return ((C0090b) this.b).getIntent();
    }

    public int getItemId() {
        return ((C0090b) this.b).getItemId();
    }

    public ContextMenuInfo getMenuInfo() {
        return ((C0090b) this.b).getMenuInfo();
    }

    public char getNumericShortcut() {
        return ((C0090b) this.b).getNumericShortcut();
    }

    public int getOrder() {
        return ((C0090b) this.b).getOrder();
    }

    public SubMenu getSubMenu() {
        return m2088a(((C0090b) this.b).getSubMenu());
    }

    public CharSequence getTitle() {
        return ((C0090b) this.b).getTitle();
    }

    public CharSequence getTitleCondensed() {
        return ((C0090b) this.b).getTitleCondensed();
    }

    public boolean hasSubMenu() {
        return ((C0090b) this.b).hasSubMenu();
    }

    public boolean isActionViewExpanded() {
        return ((C0090b) this.b).isActionViewExpanded();
    }

    public boolean isCheckable() {
        return ((C0090b) this.b).isCheckable();
    }

    public boolean isChecked() {
        return ((C0090b) this.b).isChecked();
    }

    public boolean isEnabled() {
        return ((C0090b) this.b).isEnabled();
    }

    public boolean isVisible() {
        return ((C0090b) this.b).isVisible();
    }

    public MenuItem setActionProvider(ActionProvider actionProvider) {
        ((C0090b) this.b).m570a(actionProvider != null ? m2240a(actionProvider) : null);
        return this;
    }

    public MenuItem setActionView(int i) {
        ((C0090b) this.b).setActionView(i);
        View actionView = ((C0090b) this.b).getActionView();
        if (actionView instanceof CollapsibleActionView) {
            ((C0090b) this.b).setActionView(new C0276q(actionView));
        }
        return this;
    }

    public MenuItem setActionView(View view) {
        if (view instanceof CollapsibleActionView) {
            view = new C0276q(view);
        }
        ((C0090b) this.b).setActionView(view);
        return this;
    }

    public MenuItem setAlphabeticShortcut(char c) {
        ((C0090b) this.b).setAlphabeticShortcut(c);
        return this;
    }

    public MenuItem setCheckable(boolean z) {
        ((C0090b) this.b).setCheckable(z);
        return this;
    }

    public MenuItem setChecked(boolean z) {
        ((C0090b) this.b).setChecked(z);
        return this;
    }

    public MenuItem setEnabled(boolean z) {
        ((C0090b) this.b).setEnabled(z);
        return this;
    }

    public MenuItem setIcon(int i) {
        ((C0090b) this.b).setIcon(i);
        return this;
    }

    public MenuItem setIcon(Drawable drawable) {
        ((C0090b) this.b).setIcon(drawable);
        return this;
    }

    public MenuItem setIntent(Intent intent) {
        ((C0090b) this.b).setIntent(intent);
        return this;
    }

    public MenuItem setNumericShortcut(char c) {
        ((C0090b) this.b).setNumericShortcut(c);
        return this;
    }

    public MenuItem setOnActionExpandListener(OnActionExpandListener onActionExpandListener) {
        ((C0090b) this.b).m569a(onActionExpandListener != null ? new C0277r(this, onActionExpandListener) : null);
        return this;
    }

    public MenuItem setOnMenuItemClickListener(OnMenuItemClickListener onMenuItemClickListener) {
        ((C0090b) this.b).setOnMenuItemClickListener(onMenuItemClickListener != null ? new C0278s(this, onMenuItemClickListener) : null);
        return this;
    }

    public MenuItem setShortcut(char c, char c2) {
        ((C0090b) this.b).setShortcut(c, c2);
        return this;
    }

    public void setShowAsAction(int i) {
        ((C0090b) this.b).setShowAsAction(i);
    }

    public MenuItem setShowAsActionFlags(int i) {
        ((C0090b) this.b).setShowAsActionFlags(i);
        return this;
    }

    public MenuItem setTitle(int i) {
        ((C0090b) this.b).setTitle(i);
        return this;
    }

    public MenuItem setTitle(CharSequence charSequence) {
        ((C0090b) this.b).setTitle(charSequence);
        return this;
    }

    public MenuItem setTitleCondensed(CharSequence charSequence) {
        ((C0090b) this.b).setTitleCondensed(charSequence);
        return this;
    }

    public MenuItem setVisible(boolean z) {
        return ((C0090b) this.b).setVisible(z);
    }
}
