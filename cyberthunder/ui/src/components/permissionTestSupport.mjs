/** Handler-test fixture; real control/ARIA behavior is tested separately with rendered Mantine widgets. */
export function permissionFixture(actions = true) {
  const state = { actions };
  const can = (requirement) => {
    const wanted = typeof requirement === 'string' ? [requirement] : requirement;
    return wanted.length > 0 && wanted.every((action) => state.actions === true || state.actions.includes(action));
  };
  const reason = (requirement) => can(requirement) ? null : `Your account lacks ${[requirement].flat().join(', ')} permission.`;
  return { state, imports: { PermissionButton: 'Button', PermissionGate: 'PermissionGate', PermissionConfirm: 'ConfirmReasonModal',
    usePermissions: () => ({ can, reason }) } };
}
