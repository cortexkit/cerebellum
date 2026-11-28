use super::*;

#[cfg(test)]
mod tests;

const IID_TOGGLE: GUID = GUID::from_u128(0x94cf8058_9b8d_4ab9_8bfd_4cd0a33c8c70);
const IID_SELECTION_ITEM: GUID = GUID::from_u128(0xa8efa66a_0fda_421a_9194_38021f3578ea);
const IID_EXPAND_COLLAPSE: GUID = GUID::from_u128(0x619be086_1f4e_4ee4_bafa_210128738730);

impl ScopedUia {
    pub fn invoke_at<E: From<Failure>>(
        &self,
        window: u32,
        runtime_id: &[i32],
        before: impl FnOnce(&UiaElementRef) -> Result<(), E>,
    ) -> Result<(), E> {
        let (element, pattern) = self.pattern_at(
            window,
            runtime_id,
            UIA_InvokePatternId,
            &IID_IUI_AUTOMATION_INVOKE_PATTERN,
        )?;
        self.call_action(&element, &pattern, INVOKE_PATTERN_INVOKE, before)
    }

    pub fn toggle_at<E: From<Failure>>(
        &self,
        window: u32,
        runtime_id: &[i32],
        before: impl FnOnce(&UiaElementRef) -> Result<(), E>,
    ) -> Result<(), E> {
        let (element, pattern) =
            self.pattern_at(window, runtime_id, UIA_TogglePatternId, &IID_TOGGLE)?;
        self.call_action(&element, &pattern, 3, before)
    }

    pub fn select_item_at<E: From<Failure>>(
        &self,
        window: u32,
        runtime_id: &[i32],
        before: impl FnOnce(&UiaElementRef) -> Result<(), E>,
    ) -> Result<(), E> {
        let (element, pattern) = self.pattern_at(
            window,
            runtime_id,
            UIA_SelectionItemPatternId,
            &IID_SELECTION_ITEM,
        )?;
        self.call_action(&element, &pattern, 3, before)
    }

    /// Pass the element's current ExpandCollapse state to the caller. Its
    /// answer selects Expand (true) or Collapse (false) on this interface only.
    pub fn expand_collapse_at<E: From<Failure>>(
        &self,
        window: u32,
        runtime_id: &[i32],
        direction: impl FnOnce(&UiaElementRef, i32) -> Result<bool, E>,
    ) -> Result<(), E> {
        let (element, pattern) = self.pattern_at(
            window,
            runtime_id,
            UIA_ExpandCollapsePatternId,
            &IID_EXPAND_COLLAPSE,
        )?;
        self.prepare()?;
        let state = self.source.element_i32(&pattern, 5)?;
        let expand = direction(&element, state)?;
        self.call_action(&element, &pattern, if expand { 3 } else { 4 }, |_| Ok(()))
    }

    pub fn set_value_at<E: From<Failure>>(
        &self,
        window: u32,
        runtime_id: &[i32],
        value: &str,
        before: impl FnOnce(&UiaElementRef, bool) -> Result<(), E>,
    ) -> Result<(), E> {
        let (element, pattern) =
            self.pattern_at(window, runtime_id, UIA_ValuePatternId, &IID_VALUE)?;
        // SetValue takes a NUL-terminated LPCWSTR, so an interior NUL would
        // silently send only part of the requested value.
        let mut text: Vec<_> = value.encode_utf16().collect();
        if text.contains(&0) {
            return Err(Failure::IncompatiblePlatformValue.into());
        }
        text.push(0);
        self.prepare()?;
        let read_only = self.source.element_bool(&pattern, 5)?;
        before(&element, read_only)?;
        self.deadline.remaining()?;
        type Method = unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT;
        // SAFETY: Slot 3 is IUIAutomationValuePattern::SetValue. The wide
        // string and queried pattern object both outlive the call.
        let result = unsafe {
            let method: Method = mem::transmute(pattern.slot(3));
            method(pattern.as_raw(), text.as_ptr())
        };
        self.mutation_result(result).map_err(E::from)
    }

    fn pattern_at(
        &self,
        window: u32,
        runtime_id: &[i32],
        id: i32,
        iid: &GUID,
    ) -> Result<(UiaElementRef, ComPtr), Failure> {
        // Search only this window's control view. Names are not element keys.
        let element = self
            .find_runtime(self.at_window(window)?, runtime_id, 63, &mut 10_000)?
            .ok_or(Failure::TargetGone)?;
        let pattern = self
            .pattern(&element, id, Some(iid))?
            .ok_or(Failure::IncompatiblePlatformValue)?;
        Ok((element, pattern))
    }

    fn find_runtime(
        &self,
        element: UiaElementRef,
        wanted: &[i32],
        depth: usize,
        remaining: &mut usize,
    ) -> Result<Option<UiaElementRef>, Failure> {
        *remaining = remaining.checked_sub(1).ok_or(Failure::TreeExceedsBound)?;
        if self.runtime_id(&element)?.as_deref() == Some(wanted) {
            return Ok(Some(element));
        }
        let mut next = self.child(&element)?;
        while let Some(child) = next {
            next = self.sibling(&child)?;
            if let Some(found) = self.find_runtime(
                child,
                wanted,
                depth.checked_sub(1).ok_or(Failure::TreeExceedsBound)?,
                remaining,
            )? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn call_action<E: From<Failure>>(
        &self,
        element: &UiaElementRef,
        pattern: &ComPtr,
        slot: usize,
        before: impl FnOnce(&UiaElementRef) -> Result<(), E>,
    ) -> Result<(), E> {
        self.prepare()?;
        before(element)?;
        self.deadline.remaining()?;
        type Method = unsafe extern "system" fn(*mut c_void) -> HRESULT;
        // SAFETY: Each caller queries the fixed interface whose action slot
        // it supplies. These action methods take only the live COM receiver.
        let result = unsafe {
            let method: Method = mem::transmute(pattern.slot(slot));
            method(pattern.as_raw())
        };
        self.mutation_result(result).map_err(E::from)
    }

    fn mutation_result(&self, code: HRESULT) -> Result<(), Failure> {
        if code == UIA_E_ELEMENTNOTAVAILABLE as HRESULT {
            return Err(Failure::TargetGone);
        }
        hresult(code).map_err(|code| self.map(code))
    }
}
