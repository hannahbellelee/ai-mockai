/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace IO.Swagger.Models
{
    /// <summary>
    /// 
    /// </summary>
    [DataContract]
    public partial class CreateCompletionRequest : IEquatable<CreateCompletionRequest>
    { 
        /// <summary>
        /// ID of the model to use. You can use the [List models](/docs/api-reference/models/list) API to see all of your available models, or see our [Model overview](/docs/models/overview) for descriptions of them. 
        /// </summary>
        /// <value>ID of the model to use. You can use the [List models](/docs/api-reference/models/list) API to see all of your available models, or see our [Model overview](/docs/models/overview) for descriptions of them. </value>
        [Required]

        [DataMember(Name="model")]
        public AnyOfCreateCompletionRequestModel Model { get; set; }

        /// <summary>
        /// The prompt(s) to generate completions for, encoded as a string, array of strings, array of tokens, or array of token arrays.  Note that &lt;|endoftext|&gt; is the document separator that the model sees during training, so if a prompt is not specified the model will generate as if from the beginning of a new document. 
        /// </summary>
        /// <value>The prompt(s) to generate completions for, encoded as a string, array of strings, array of tokens, or array of token arrays.  Note that &lt;|endoftext|&gt; is the document separator that the model sees during training, so if a prompt is not specified the model will generate as if from the beginning of a new document. </value>
        [Required]

        [DataMember(Name="prompt")]
        public OneOfCreateCompletionRequestPrompt Prompt { get; set; }

        /// <summary>
        /// Generates &#x60;best_of&#x60; completions server-side and returns the \&quot;best\&quot; (the one with the highest log probability per token). Results cannot be streamed.  When used with &#x60;n&#x60;, &#x60;best_of&#x60; controls the number of candidate completions and &#x60;n&#x60; specifies how many to return – &#x60;best_of&#x60; must be greater than &#x60;n&#x60;.  **Note:** Because this parameter generates many completions, it can quickly consume your token quota. Use carefully and ensure that you have reasonable settings for &#x60;max_tokens&#x60; and &#x60;stop&#x60;. 
        /// </summary>
        /// <value>Generates &#x60;best_of&#x60; completions server-side and returns the \&quot;best\&quot; (the one with the highest log probability per token). Results cannot be streamed.  When used with &#x60;n&#x60;, &#x60;best_of&#x60; controls the number of candidate completions and &#x60;n&#x60; specifies how many to return – &#x60;best_of&#x60; must be greater than &#x60;n&#x60;.  **Note:** Because this parameter generates many completions, it can quickly consume your token quota. Use carefully and ensure that you have reasonable settings for &#x60;max_tokens&#x60; and &#x60;stop&#x60;. </value>

        [Range(0, 20)]
        [DataMember(Name="best_of")]
        public int? BestOf { get; set; }

        /// <summary>
        /// Echo back the prompt in addition to the completion 
        /// </summary>
        /// <value>Echo back the prompt in addition to the completion </value>

        [DataMember(Name="echo")]
        public bool? Echo { get; set; }

        /// <summary>
        /// Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far, decreasing the model&#x27;s likelihood to repeat the same line verbatim.  [See more information about frequency and presence penalties.](/docs/guides/text-generation/parameter-details) 
        /// </summary>
        /// <value>Number between -2.0 and 2.0. Positive values penalize new tokens based on their existing frequency in the text so far, decreasing the model&#x27;s likelihood to repeat the same line verbatim.  [See more information about frequency and presence penalties.](/docs/guides/text-generation/parameter-details) </value>

        [Range(-2, 2)]
        [DataMember(Name="frequency_penalty")]
        public decimal? FrequencyPenalty { get; set; }

        /// <summary>
        /// Modify the likelihood of specified tokens appearing in the completion.  Accepts a JSON object that maps tokens (specified by their token ID in the GPT tokenizer) to an associated bias value from -100 to 100. You can use this [tokenizer tool](/tokenizer?view&#x3D;bpe) to convert text to token IDs. Mathematically, the bias is added to the logits generated by the model prior to sampling. The exact effect will vary per model, but values between -1 and 1 should decrease or increase likelihood of selection; values like -100 or 100 should result in a ban or exclusive selection of the relevant token.  As an example, you can pass &#x60;{\&quot;50256\&quot;: -100}&#x60; to prevent the &lt;|endoftext|&gt; token from being generated. 
        /// </summary>
        /// <value>Modify the likelihood of specified tokens appearing in the completion.  Accepts a JSON object that maps tokens (specified by their token ID in the GPT tokenizer) to an associated bias value from -100 to 100. You can use this [tokenizer tool](/tokenizer?view&#x3D;bpe) to convert text to token IDs. Mathematically, the bias is added to the logits generated by the model prior to sampling. The exact effect will vary per model, but values between -1 and 1 should decrease or increase likelihood of selection; values like -100 or 100 should result in a ban or exclusive selection of the relevant token.  As an example, you can pass &#x60;{\&quot;50256\&quot;: -100}&#x60; to prevent the &lt;|endoftext|&gt; token from being generated. </value>

        [DataMember(Name="logit_bias")]
        public Dictionary<string, int?> LogitBias { get; set; }

        /// <summary>
        /// Include the log probabilities on the &#x60;logprobs&#x60; most likely output tokens, as well the chosen tokens. For example, if &#x60;logprobs&#x60; is 5, the API will return a list of the 5 most likely tokens. The API will always return the &#x60;logprob&#x60; of the sampled token, so there may be up to &#x60;logprobs+1&#x60; elements in the response.  The maximum value for &#x60;logprobs&#x60; is 5. 
        /// </summary>
        /// <value>Include the log probabilities on the &#x60;logprobs&#x60; most likely output tokens, as well the chosen tokens. For example, if &#x60;logprobs&#x60; is 5, the API will return a list of the 5 most likely tokens. The API will always return the &#x60;logprob&#x60; of the sampled token, so there may be up to &#x60;logprobs+1&#x60; elements in the response.  The maximum value for &#x60;logprobs&#x60; is 5. </value>

        [Range(0, 5)]
        [DataMember(Name="logprobs")]
        public int? Logprobs { get; set; }

        /// <summary>
        /// The maximum number of [tokens](/tokenizer) that can be generated in the completion.  The token count of your prompt plus &#x60;max_tokens&#x60; cannot exceed the model&#x27;s context length. [Example Python code](https://cookbook.openai.com/examples/how_to_count_tokens_with_tiktoken) for counting tokens. 
        /// </summary>
        /// <value>The maximum number of [tokens](/tokenizer) that can be generated in the completion.  The token count of your prompt plus &#x60;max_tokens&#x60; cannot exceed the model&#x27;s context length. [Example Python code](https://cookbook.openai.com/examples/how_to_count_tokens_with_tiktoken) for counting tokens. </value>

        [DataMember(Name="max_tokens")]
        public int? MaxTokens { get; set; }

        /// <summary>
        /// How many completions to generate for each prompt.  **Note:** Because this parameter generates many completions, it can quickly consume your token quota. Use carefully and ensure that you have reasonable settings for &#x60;max_tokens&#x60; and &#x60;stop&#x60;. 
        /// </summary>
        /// <value>How many completions to generate for each prompt.  **Note:** Because this parameter generates many completions, it can quickly consume your token quota. Use carefully and ensure that you have reasonable settings for &#x60;max_tokens&#x60; and &#x60;stop&#x60;. </value>

        [Range(1, 128)]
        [DataMember(Name="n")]
        public int? N { get; set; }

        /// <summary>
        /// Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far, increasing the model&#x27;s likelihood to talk about new topics.  [See more information about frequency and presence penalties.](/docs/guides/text-generation/parameter-details) 
        /// </summary>
        /// <value>Number between -2.0 and 2.0. Positive values penalize new tokens based on whether they appear in the text so far, increasing the model&#x27;s likelihood to talk about new topics.  [See more information about frequency and presence penalties.](/docs/guides/text-generation/parameter-details) </value>

        [Range(-2, 2)]
        [DataMember(Name="presence_penalty")]
        public decimal? PresencePenalty { get; set; }

        /// <summary>
        /// If specified, our system will make a best effort to sample deterministically, such that repeated requests with the same &#x60;seed&#x60; and parameters should return the same result.  Determinism is not guaranteed, and you should refer to the &#x60;system_fingerprint&#x60; response parameter to monitor changes in the backend. 
        /// </summary>
        /// <value>If specified, our system will make a best effort to sample deterministically, such that repeated requests with the same &#x60;seed&#x60; and parameters should return the same result.  Determinism is not guaranteed, and you should refer to the &#x60;system_fingerprint&#x60; response parameter to monitor changes in the backend. </value>

        [Range(9223372036854775616, -9223372036854775616)]
        [DataMember(Name="seed")]
        public int? Seed { get; set; }

        /// <summary>
        /// Up to 4 sequences where the API will stop generating further tokens. The returned text will not contain the stop sequence. 
        /// </summary>
        /// <value>Up to 4 sequences where the API will stop generating further tokens. The returned text will not contain the stop sequence. </value>

        [DataMember(Name="stop")]
        public OneOfCreateCompletionRequestStop Stop { get; set; }

        /// <summary>
        /// Whether to stream back partial progress. If set, tokens will be sent as data-only [server-sent events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#Event_stream_format) as they become available, with the stream terminated by a &#x60;data: [DONE]&#x60; message. [Example Python code](https://cookbook.openai.com/examples/how_to_stream_completions). 
        /// </summary>
        /// <value>Whether to stream back partial progress. If set, tokens will be sent as data-only [server-sent events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#Event_stream_format) as they become available, with the stream terminated by a &#x60;data: [DONE]&#x60; message. [Example Python code](https://cookbook.openai.com/examples/how_to_stream_completions). </value>

        [DataMember(Name="stream")]
        public bool? Stream { get; set; }

        /// <summary>
        /// Gets or Sets StreamOptions
        /// </summary>

        [DataMember(Name="stream_options")]
        public ChatCompletionStreamOptions StreamOptions { get; set; }

        /// <summary>
        /// The suffix that comes after a completion of inserted text.  This parameter is only supported for &#x60;gpt-3.5-turbo-instruct&#x60;. 
        /// </summary>
        /// <value>The suffix that comes after a completion of inserted text.  This parameter is only supported for &#x60;gpt-3.5-turbo-instruct&#x60;. </value>

        [DataMember(Name="suffix")]
        public string Suffix { get; set; }

        /// <summary>
        /// What sampling temperature to use, between 0 and 2. Higher values like 0.8 will make the output more random, while lower values like 0.2 will make it more focused and deterministic.  We generally recommend altering this or &#x60;top_p&#x60; but not both. 
        /// </summary>
        /// <value>What sampling temperature to use, between 0 and 2. Higher values like 0.8 will make the output more random, while lower values like 0.2 will make it more focused and deterministic.  We generally recommend altering this or &#x60;top_p&#x60; but not both. </value>

        [Range(0, 2)]
        [DataMember(Name="temperature")]
        public decimal? Temperature { get; set; }

        /// <summary>
        /// An alternative to sampling with temperature, called nucleus sampling, where the model considers the results of the tokens with top_p probability mass. So 0.1 means only the tokens comprising the top 10% probability mass are considered.  We generally recommend altering this or &#x60;temperature&#x60; but not both. 
        /// </summary>
        /// <value>An alternative to sampling with temperature, called nucleus sampling, where the model considers the results of the tokens with top_p probability mass. So 0.1 means only the tokens comprising the top 10% probability mass are considered.  We generally recommend altering this or &#x60;temperature&#x60; but not both. </value>

        [Range(0, 1)]
        [DataMember(Name="top_p")]
        public decimal? TopP { get; set; }

        /// <summary>
        /// A unique identifier representing your end-user, which can help OpenAI to monitor and detect abuse. [Learn more](/docs/guides/safety-best-practices/end-user-ids). 
        /// </summary>
        /// <value>A unique identifier representing your end-user, which can help OpenAI to monitor and detect abuse. [Learn more](/docs/guides/safety-best-practices/end-user-ids). </value>

        [DataMember(Name="user")]
        public string User { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CreateCompletionRequest {\n");
            sb.Append("  Model: ").Append(Model).Append("\n");
            sb.Append("  Prompt: ").Append(Prompt).Append("\n");
            sb.Append("  BestOf: ").Append(BestOf).Append("\n");
            sb.Append("  Echo: ").Append(Echo).Append("\n");
            sb.Append("  FrequencyPenalty: ").Append(FrequencyPenalty).Append("\n");
            sb.Append("  LogitBias: ").Append(LogitBias).Append("\n");
            sb.Append("  Logprobs: ").Append(Logprobs).Append("\n");
            sb.Append("  MaxTokens: ").Append(MaxTokens).Append("\n");
            sb.Append("  N: ").Append(N).Append("\n");
            sb.Append("  PresencePenalty: ").Append(PresencePenalty).Append("\n");
            sb.Append("  Seed: ").Append(Seed).Append("\n");
            sb.Append("  Stop: ").Append(Stop).Append("\n");
            sb.Append("  Stream: ").Append(Stream).Append("\n");
            sb.Append("  StreamOptions: ").Append(StreamOptions).Append("\n");
            sb.Append("  Suffix: ").Append(Suffix).Append("\n");
            sb.Append("  Temperature: ").Append(Temperature).Append("\n");
            sb.Append("  TopP: ").Append(TopP).Append("\n");
            sb.Append("  User: ").Append(User).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((CreateCompletionRequest)obj);
        }

        /// <summary>
        /// Returns true if CreateCompletionRequest instances are equal
        /// </summary>
        /// <param name="other">Instance of CreateCompletionRequest to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CreateCompletionRequest other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Model == other.Model ||
                    Model != null &&
                    Model.Equals(other.Model)
                ) && 
                (
                    Prompt == other.Prompt ||
                    Prompt != null &&
                    Prompt.Equals(other.Prompt)
                ) && 
                (
                    BestOf == other.BestOf ||
                    BestOf != null &&
                    BestOf.Equals(other.BestOf)
                ) && 
                (
                    Echo == other.Echo ||
                    Echo != null &&
                    Echo.Equals(other.Echo)
                ) && 
                (
                    FrequencyPenalty == other.FrequencyPenalty ||
                    FrequencyPenalty != null &&
                    FrequencyPenalty.Equals(other.FrequencyPenalty)
                ) && 
                (
                    LogitBias == other.LogitBias ||
                    LogitBias != null &&
                    LogitBias.SequenceEqual(other.LogitBias)
                ) && 
                (
                    Logprobs == other.Logprobs ||
                    Logprobs != null &&
                    Logprobs.Equals(other.Logprobs)
                ) && 
                (
                    MaxTokens == other.MaxTokens ||
                    MaxTokens != null &&
                    MaxTokens.Equals(other.MaxTokens)
                ) && 
                (
                    N == other.N ||
                    N != null &&
                    N.Equals(other.N)
                ) && 
                (
                    PresencePenalty == other.PresencePenalty ||
                    PresencePenalty != null &&
                    PresencePenalty.Equals(other.PresencePenalty)
                ) && 
                (
                    Seed == other.Seed ||
                    Seed != null &&
                    Seed.Equals(other.Seed)
                ) && 
                (
                    Stop == other.Stop ||
                    Stop != null &&
                    Stop.Equals(other.Stop)
                ) && 
                (
                    Stream == other.Stream ||
                    Stream != null &&
                    Stream.Equals(other.Stream)
                ) && 
                (
                    StreamOptions == other.StreamOptions ||
                    StreamOptions != null &&
                    StreamOptions.Equals(other.StreamOptions)
                ) && 
                (
                    Suffix == other.Suffix ||
                    Suffix != null &&
                    Suffix.Equals(other.Suffix)
                ) && 
                (
                    Temperature == other.Temperature ||
                    Temperature != null &&
                    Temperature.Equals(other.Temperature)
                ) && 
                (
                    TopP == other.TopP ||
                    TopP != null &&
                    TopP.Equals(other.TopP)
                ) && 
                (
                    User == other.User ||
                    User != null &&
                    User.Equals(other.User)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    if (Model != null)
                    hashCode = hashCode * 59 + Model.GetHashCode();
                    if (Prompt != null)
                    hashCode = hashCode * 59 + Prompt.GetHashCode();
                    if (BestOf != null)
                    hashCode = hashCode * 59 + BestOf.GetHashCode();
                    if (Echo != null)
                    hashCode = hashCode * 59 + Echo.GetHashCode();
                    if (FrequencyPenalty != null)
                    hashCode = hashCode * 59 + FrequencyPenalty.GetHashCode();
                    if (LogitBias != null)
                    hashCode = hashCode * 59 + LogitBias.GetHashCode();
                    if (Logprobs != null)
                    hashCode = hashCode * 59 + Logprobs.GetHashCode();
                    if (MaxTokens != null)
                    hashCode = hashCode * 59 + MaxTokens.GetHashCode();
                    if (N != null)
                    hashCode = hashCode * 59 + N.GetHashCode();
                    if (PresencePenalty != null)
                    hashCode = hashCode * 59 + PresencePenalty.GetHashCode();
                    if (Seed != null)
                    hashCode = hashCode * 59 + Seed.GetHashCode();
                    if (Stop != null)
                    hashCode = hashCode * 59 + Stop.GetHashCode();
                    if (Stream != null)
                    hashCode = hashCode * 59 + Stream.GetHashCode();
                    if (StreamOptions != null)
                    hashCode = hashCode * 59 + StreamOptions.GetHashCode();
                    if (Suffix != null)
                    hashCode = hashCode * 59 + Suffix.GetHashCode();
                    if (Temperature != null)
                    hashCode = hashCode * 59 + Temperature.GetHashCode();
                    if (TopP != null)
                    hashCode = hashCode * 59 + TopP.GetHashCode();
                    if (User != null)
                    hashCode = hashCode * 59 + User.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(CreateCompletionRequest left, CreateCompletionRequest right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CreateCompletionRequest left, CreateCompletionRequest right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
