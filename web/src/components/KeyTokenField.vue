<script setup lang="ts">
import { computed, ref } from 'vue'
import CopyButton from './CopyButton.vue'
import ConfirmDialog from './ConfirmDialog.vue'

/**
 * One per-key server-side credential (stats token, verify secret): issued,
 * shown once right after, then only its display prefix comes back from the
 * server. Regenerating and revoking ask for confirmation first.
 */
const props = defineProps<{
  /** Name of the credential, e.g. "Stats token". The caller renders it as
   *  the <dt>: this component is the <dd>, so it can sit directly in a <dl>. */
  label: string
  /** Leading characters of the live credential, empty when none is issued. */
  display: string
  issue: () => Promise<string>
  revoke: () => Promise<void>
  /** What stops working when the current credential is replaced or revoked. */
  consequence: string
}>()

const emit = defineEmits<{ changed: [] }>()

const fresh = ref('')
const confirming = ref<'reissue' | 'revoke' | null>(null)
const busy = ref(false)
const noun = computed(() => props.label.toLowerCase())

async function run(action: () => Promise<void>) {
  if (busy.value) return
  busy.value = true
  try {
    await action()
    emit('changed')
  } finally {
    busy.value = false
    confirming.value = null
  }
}

const doIssue = () => run(async () => { fresh.value = await props.issue() })
const doRevoke = () => run(async () => { await props.revoke(); fresh.value = '' })
</script>

<template>
  <dd class="mt-1">
    <div v-if="fresh" class="flex flex-wrap items-center gap-2">
      <code class="text-sm bg-sunken px-2 py-1 rounded font-mono break-all">{{ fresh }}</code>
      <CopyButton :value="fresh" :label="`Copy ${noun}`" />
    </div>
    <div v-else class="flex flex-wrap items-center gap-2">
      <code v-if="display" class="text-sm bg-sunken px-2 py-1 rounded font-mono">{{ display }}…</code>
      <span v-else class="text-sm text-ink-2">None</span>
      <button
        v-if="!display"
        @click="doIssue"
        :disabled="busy"
        class="inline-flex min-h-8 items-center px-2 text-xs font-semibold text-link hover:text-link-hover"
      >Generate</button>
      <template v-else>
        <button @click="confirming = 'reissue'" class="inline-flex min-h-8 items-center px-2 text-xs text-link hover:text-link-hover">Regenerate</button>
        <button @click="confirming = 'revoke'" class="inline-flex min-h-8 items-center px-2 text-xs font-semibold text-fail hover:text-ink">Revoke</button>
      </template>
    </div>
    <p class="mt-1 text-xs text-muted">
      <template v-if="fresh">Copy it now: it is not shown again.</template>
      <slot />
    </p>

    <ConfirmDialog
      :open="confirming !== null"
      :title="confirming === 'revoke' ? `Revoke ${noun}?` : `Regenerate ${noun}?`"
      :confirm-label="confirming === 'revoke' ? 'Revoke' : 'Regenerate'"
      :tone="confirming === 'revoke' ? 'danger' : 'primary'"
      :busy="busy"
      @cancel="confirming = null"
      @confirm="confirming === 'revoke' ? doRevoke() : doIssue()"
    >
      {{ consequence }} {{ confirming === 'revoke' ? 'a new one' : 'the new one' }}.
    </ConfirmDialog>
  </dd>
</template>
