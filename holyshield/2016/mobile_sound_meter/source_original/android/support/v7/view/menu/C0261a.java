package android.support.v7.view.menu;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.support.v4.p002b.C0020a;
import android.support.v4.p004h.C0161n;
import android.support.v4.p004h.aw;
import android.support.v4.p008d.p009a.C0090b;
import android.view.ActionProvider;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.MenuItem;
import android.view.MenuItem.OnActionExpandListener;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.SubMenu;
import android.view.View;

/* renamed from: android.support.v7.view.menu.a */
public class C0261a implements C0090b {
    private final int f939a;
    private final int f940b;
    private final int f941c;
    private final int f942d;
    private CharSequence f943e;
    private CharSequence f944f;
    private Intent f945g;
    private char f946h;
    private char f947i;
    private Drawable f948j;
    private int f949k;
    private Context f950l;
    private OnMenuItemClickListener f951m;
    private int f952n;

    public C0261a(Context context, int i, int i2, int i3, int i4, CharSequence charSequence) {
        this.f949k = 0;
        this.f952n = 16;
        this.f950l = context;
        this.f939a = i2;
        this.f940b = i;
        this.f941c = i3;
        this.f942d = i4;
        this.f943e = charSequence;
    }

    public C0090b m2078a(int i) {
        throw new UnsupportedOperationException();
    }

    public C0090b m2079a(aw awVar) {
        return this;
    }

    public C0090b m2080a(C0161n c0161n) {
        throw new UnsupportedOperationException();
    }

    public C0090b m2081a(View view) {
        throw new UnsupportedOperationException();
    }

    public C0161n m2082a() {
        return null;
    }

    public C0090b m2083b(int i) {
        setShowAsAction(i);
        return this;
    }

    public boolean collapseActionView() {
        return false;
    }

    public boolean expandActionView() {
        return false;
    }

    public ActionProvider getActionProvider() {
        throw new UnsupportedOperationException();
    }

    public View getActionView() {
        return null;
    }

    public char getAlphabeticShortcut() {
        return this.f947i;
    }

    public int getGroupId() {
        return this.f940b;
    }

    public Drawable getIcon() {
        return this.f948j;
    }

    public Intent getIntent() {
        return this.f945g;
    }

    public int getItemId() {
        return this.f939a;
    }

    public ContextMenuInfo getMenuInfo() {
        return null;
    }

    public char getNumericShortcut() {
        return this.f946h;
    }

    public int getOrder() {
        return this.f942d;
    }

    public SubMenu getSubMenu() {
        return null;
    }

    public CharSequence getTitle() {
        return this.f943e;
    }

    public CharSequence getTitleCondensed() {
        return this.f944f != null ? this.f944f : this.f943e;
    }

    public boolean hasSubMenu() {
        return false;
    }

    public boolean isActionViewExpanded() {
        return false;
    }

    public boolean isCheckable() {
        return (this.f952n & 1) != 0;
    }

    public boolean isChecked() {
        return (this.f952n & 2) != 0;
    }

    public boolean isEnabled() {
        return (this.f952n & 16) != 0;
    }

    public boolean isVisible() {
        return (this.f952n & 8) == 0;
    }

    public MenuItem setActionProvider(ActionProvider actionProvider) {
        throw new UnsupportedOperationException();
    }

    public /* synthetic */ MenuItem setActionView(int i) {
        return m2078a(i);
    }

    public /* synthetic */ MenuItem setActionView(View view) {
        return m2081a(view);
    }

    public MenuItem setAlphabeticShortcut(char c) {
        this.f947i = c;
        return this;
    }

    public MenuItem setCheckable(boolean z) {
        this.f952n = (z ? 1 : 0) | (this.f952n & -2);
        return this;
    }

    public MenuItem setChecked(boolean z) {
        this.f952n = (z ? 2 : 0) | (this.f952n & -3);
        return this;
    }

    public MenuItem setEnabled(boolean z) {
        this.f952n = (z ? 16 : 0) | (this.f952n & -17);
        return this;
    }

    public MenuItem setIcon(int i) {
        this.f949k = i;
        this.f948j = C0020a.m74a(this.f950l, i);
        return this;
    }

    public MenuItem setIcon(Drawable drawable) {
        this.f948j = drawable;
        this.f949k = 0;
        return this;
    }

    public MenuItem setIntent(Intent intent) {
        this.f945g = intent;
        return this;
    }

    public MenuItem setNumericShortcut(char c) {
        this.f946h = c;
        return this;
    }

    public MenuItem setOnActionExpandListener(OnActionExpandListener onActionExpandListener) {
        throw new UnsupportedOperationException();
    }

    public MenuItem setOnMenuItemClickListener(OnMenuItemClickListener onMenuItemClickListener) {
        this.f951m = onMenuItemClickListener;
        return this;
    }

    public MenuItem setShortcut(char c, char c2) {
        this.f946h = c;
        this.f947i = c2;
        return this;
    }

    public void setShowAsAction(int i) {
    }

    public /* synthetic */ MenuItem setShowAsActionFlags(int i) {
        return m2083b(i);
    }

    public MenuItem setTitle(int i) {
        this.f943e = this.f950l.getResources().getString(i);
        return this;
    }

    public MenuItem setTitle(CharSequence charSequence) {
        this.f943e = charSequence;
        return this;
    }

    public MenuItem setTitleCondensed(CharSequence charSequence) {
        this.f944f = charSequence;
        return this;
    }

    public MenuItem setVisible(boolean z) {
        this.f952n = (z ? 0 : 8) | (this.f952n & 8);
        return this;
    }
}
